//! Windows: the service manager (SCM), when it started the daemon. `connect`
//! calls the SCM's dispatcher on its own thread. In a console the call fails
//! at once, and the daemon runs as a console daemon that stops on Ctrl-C or
//! Ctrl-Break (see `stop`). Under the SCM, the dispatcher starts a new thread
//! for `service_main`, which reports the service's state. The control
//! handler runs on the dispatcher thread, and turns the SCM's stop and
//! pre-shutdown requests into `stop_requested`.

use std::{
    ffi::c_void,
    io, ptr,
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tokio::sync::{Notify, oneshot};
use tracing::{error, warn};
use windows_sys::{
    Win32::{
        Foundation::{
            ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
            ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
        },
        System::Services::{
            RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_PRESHUTDOWN, SERVICE_ACCEPT_STOP,
            SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PRESHUTDOWN, SERVICE_CONTROL_STOP,
            SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
            SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
            SetServiceStatus, StartServiceCtrlDispatcherW,
        },
    },
    core::{PCWSTR, PWSTR, w},
};

use super::BoxedLayer;

mod event_log;
use event_log::EventLog;

/// The service's name. The SCM ignores it for a service that runs in its own
/// process.
const NAME: PCWSTR = w!("cheesecloth");

/// How long a start or a stop may take, in milliseconds. It matches the
/// pre-shutdown timeout that cheesecloth.iss in the cheesecloth-windows
/// repository sets.
const WAIT_HINT_MS: u32 = 30_000;

/// The service-specific exit code of a daemon that failed.
const FAILED: u32 = 1;

/// Where `service_main` sends the session, or the dispatcher thread sends
/// `None` (a console run) or its error. The SCM calls `service_main` with no
/// user data, and there is one SCM per process.
static STARTED: Mutex<Option<oneshot::Sender<Result<Option<Session>>>>> = Mutex::new(None);

/// Notified by the SCM's stop and pre-shutdown requests. The SCM may call
/// the control handler until the process exits, even after `Stopped`, so
/// the handler uses this static and no context that could be freed.
static STOP: Notify = Notify::const_new();

pub(super) enum Service {
    Console,
    Manager {
        session: Session,
        /// Returns after `service_main` has reported `Stopped`.
        dispatcher: JoinHandle<()>,
    },
}

/// A service that the SCM started.
pub(super) struct Session {
    status: StatusHandle,
    /// Takes the exit code to `service_main`, which reports it.
    done: mpsc::Sender<u32>,
    log: Arc<EventLog>,
}

/// Drops the sender in `STARTED`, if `service_main` has not taken it, when
/// the dispatcher thread ends, also by a panic. Then `connect` does not wait
/// forever.
struct DropStarted;

impl Drop for DropStarted {
    fn drop(&mut self) {
        STARTED.lock().take();
    }
}

/// A handle from `RegisterServiceCtrlHandlerExW`. It is never closed.
#[derive(Clone, Copy)]
struct StatusHandle(SERVICE_STATUS_HANDLE);

// SAFETY: SetServiceStatus takes the handle from any thread.
#[allow(unsafe_code, reason = "SetServiceStatus is thread safe")]
unsafe impl Send for StatusHandle {}
// SAFETY: as above.
#[allow(unsafe_code, reason = "SetServiceStatus is thread safe")]
unsafe impl Sync for StatusHandle {}

/// A state that the daemon reports to the SCM.
#[derive(Clone, Copy, Debug)]
enum State {
    StartPending,
    Running,
    StopPending,
    /// With the service-specific exit code: 0 for a clean stop, or `FAILED`.
    Stopped(u32),
}

impl Service {
    pub(super) async fn connect() -> Result<Self> {
        let (started, session) = oneshot::channel();
        *STARTED.lock() = Some(started);
        let dispatcher = thread::spawn(|| {
            let _guard = DropStarted;
            let Err(e) = dispatch() else {
                return;
            };
            let result = if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32)
            {
                Ok(None)
            } else {
                Err(anyhow::Error::new(e).context("connecting to the service manager"))
            };
            if let Some(started) = STARTED.lock().take() {
                let _ = started.send(result);
            }
        });
        let session = session
            .await
            .context("the service dispatcher thread ended")??;
        Ok(match session {
            None => Self::Console,
            Some(session) => Self::Manager {
                session,
                dispatcher,
            },
        })
    }

    /// The Event Log under the SCM.
    pub(super) fn log_layer(&self) -> Option<BoxedLayer> {
        let Self::Manager { session, .. } = self else {
            return None;
        };
        Some(event_log::layer(session.log.clone()))
    }

    /// Under the SCM, sends panics to the log: a service has no stderr.
    pub(super) fn log_panics(&self) {
        if let Self::Manager { .. } = self {
            std::panic::set_hook(Box::new(|info| error!("{info}")));
        }
    }

    pub(super) fn running(&self) {
        if let Self::Manager { session, .. } = self {
            session.report(State::Running);
        }
    }

    pub(super) async fn stop_requested(&self) {
        match self {
            Self::Console => crate::stop::requested().await,
            Self::Manager { session, .. } => {
                STOP.notified().await;
                session.report(State::StopPending);
            }
        }
    }

    pub(super) async fn stopped(self, result: &Result<()>) {
        let Self::Manager {
            session,
            dispatcher,
        } = self
        else {
            return;
        };
        let exit_code = match result {
            Ok(()) => 0,
            Err(e) => {
                error!("{e:#}");
                FAILED
            }
        };
        // service_main waits for it, so the send does not fail.
        let _ = session.done.send(exit_code);
        // Stopped must be the last report before the process exits; else the
        // SCM sees a crash and restarts the service. A panic on the
        // dispatcher thread went to the panic hook already.
        let _ = tokio::task::spawn_blocking(|| dispatcher.join()).await;
    }
}

impl Session {
    /// Opens the Event Log, registers with the SCM and reports
    /// `StartPending`.
    fn start(done: mpsc::Sender<u32>) -> Result<Self> {
        let log = Arc::new(EventLog::open().context("opening the Event Log")?);
        let status = register().context("registering with the service manager")?;
        report(status, State::StartPending)?;
        Ok(Self { status, done, log })
    }

    /// Reports `state`, logging a failure.
    fn report(&self, state: State) {
        if let Err(e) = report(self.status, state) {
            warn!("{e:#}");
        }
    }
}

/// Runs on a new thread that the dispatcher starts, until the daemon has
/// stopped.
extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let Some(started) = STARTED.lock().take() else {
        return;
    };
    let (done, finished) = mpsc::channel();
    let session = match Session::start(done) {
        Ok(session) => session,
        Err(e) => {
            let _ = started.send(Err(e));
            return;
        }
    };
    let status = session.status;
    // If connect is gone, the session is dropped, and so is its sender.
    let _ = started.send(Ok(Some(session)));
    // A dropped sender means the daemon ended without a result.
    let exit_code = finished.recv().unwrap_or(FAILED);
    if let Err(e) = report(status, State::Stopped(exit_code)) {
        warn!("{e:#}");
    }
}

/// The SCM's control handler. It runs on the dispatcher thread.
extern "system" fn handler(
    control: u32,
    _event: u32,
    _data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    on_control(control, &STOP)
}

/// Answers a request from the SCM. Stop and pre-shutdown both stop the
/// daemon.
fn on_control(control: u32, stop: &Notify) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_PRESHUTDOWN => {
            stop.notify_one();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/// Runs the SCM's dispatcher, which calls `service_main` and returns after
/// the service has stopped.
#[allow(unsafe_code, reason = "windows-sys has no safe service calls")]
fn dispatch() -> io::Result<()> {
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: NAME.cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: the table ends with a null entry and lives until the call
    // returns. The SCM does not write to the name.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Registers `handler` for the SCM's requests.
#[allow(unsafe_code, reason = "windows-sys has no safe service calls")]
fn register() -> io::Result<StatusHandle> {
    // SAFETY: the name is a NUL-terminated literal, and the handler takes no
    // context.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(NAME, Some(handler), ptr::null()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(StatusHandle(handle))
}

/// Reports `state` to the SCM. Only a running service accepts requests.
#[allow(unsafe_code, reason = "windows-sys has no safe service calls")]
fn report(status: StatusHandle, state: State) -> Result<()> {
    let (current, accepted, wait_hint, exit_code) = match state {
        State::StartPending => (SERVICE_START_PENDING, 0, WAIT_HINT_MS, 0),
        State::Running => (
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN,
            0,
            0,
        ),
        State::StopPending => (SERVICE_STOP_PENDING, 0, WAIT_HINT_MS, 0),
        State::Stopped(exit_code) => (SERVICE_STOPPED, 0, 0, exit_code),
    };
    let info = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: current,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: if exit_code == 0 {
            NO_ERROR
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
        dwServiceSpecificExitCode: exit_code,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint,
    };
    // SAFETY: the handle came from RegisterServiceCtrlHandlerExW and is never
    // closed, and info lives until the call returns.
    if unsafe { SetServiceStatus(status.0, &info) } == 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("reporting {state:?} to the service manager"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
