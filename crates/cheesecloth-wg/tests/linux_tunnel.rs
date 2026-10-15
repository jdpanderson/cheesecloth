//! Real kernel and userspace WireGuard tests on Linux. They need
//! `CAP_NET_ADMIN` and `CAP_NET_RAW`, and change the network namespace they
//! run in, so run them in a new one: `unshare -rn <test binary>`.
#![cfg(target_os = "linux")]

mod common;

use anyhow::{Context, Result, ensure};
use cheesecloth_wg::{BackendKind, InterfaceConfig};
use common::*;

const NAME: &str = "cctest0";

#[test]
fn real_tunnels() -> Result<()> {
    // A new network namespace starts with loopback down; the echo peer uses it.
    command("ip", &["link", "set", "lo", "up"])?;
    for (kind, expected) in [
        (BackendKind::Kernel, "kernel"),
        (BackendKind::Userspace, "userspace"),
        (BackendKind::Auto, "kernel"),
    ] {
        println!("checking {kind:?}");
        tunnel(kind, expected).with_context(|| format!("{kind:?}"))?;
    }
    check_nat_opener()?;
    Ok(())
}

fn tunnel(kind: BackendKind, expected: &str) -> Result<()> {
    let (config, peer, remote) = tunnel_setup(NAME)?;

    let mut interface = Interface(cheesecloth_wg::open(kind, &config)?);
    let backend = &mut interface.0;
    ensure!(
        backend.kind() == expected,
        "wrong backend: {}",
        backend.kind()
    );
    // Not /sys/class/net: it shows the namespace that mounted /sys.
    ensure!(
        command("ip", &["link", "show", NAME])?.contains("mtu 1280"),
        "MTU was not applied"
    );
    for address in [REMOTE_V4, REMOTE_V6] {
        ensure!(
            command("ip", &["route", "get", address])?.contains(&format!("dev {NAME}")),
            "missing route to {address}"
        );
    }
    exercise_peer(backend.as_mut(), &peer)?;

    if kind == BackendKind::Kernel {
        // A kernel interface outlives a crashed daemon. The next start
        // replaces it.
        std::mem::forget(interface);
        ensure!(interface_exists(NAME), "the interface did not survive");
        interface = Interface(cheesecloth_wg::open(kind, &config)?);
        ensure!(
            interface.0.status()?.is_empty(),
            "the replaced interface kept its peers"
        );
        interface.0.set_peer(&peer)?;
        exchange(LOCAL_V4, REMOTE_V4)?;
        refuses_foreign_interface(&config)?;
    }

    let backend = &mut interface.0;
    backend.down().context("removing the interface")?;
    backend.down().context("repeating interface removal")?;
    ensure!(!interface_exists(NAME), "interface survived removal");
    ensure!(
        !command("ip", &["route"])?.contains(NAME),
        "route survived removal"
    );
    let actual = match expected {
        "kernel" => BackendKind::Kernel,
        _ => BackendKind::Userspace,
    };
    cheesecloth_wg::remove_existing(actual, NAME)?;
    remote.finish()
}

/// The kernel backend never deletes an interface that is not WireGuard.
fn refuses_foreign_interface(config: &InterfaceConfig) -> Result<()> {
    let name = "cctest1";
    command("ip", &["link", "add", name, "type", "dummy"])?;
    let config = InterfaceConfig {
        name: name.into(),
        ..config.clone()
    };
    let error = match cheesecloth_wg::open(BackendKind::Kernel, &config) {
        Ok(_) => anyhow::bail!("a dummy interface was replaced"),
        Err(e) => format!("{e:#}"),
    };
    ensure!(
        error.contains("not a WireGuard interface"),
        "unexpected error: {error}"
    );
    ensure!(
        cheesecloth_wg::remove_existing(BackendKind::Kernel, name).is_err(),
        "cleanup accepted a dummy interface"
    );
    ensure!(interface_exists(name), "the dummy interface was deleted");
    command("ip", &["link", "del", name])?;
    Ok(())
}
