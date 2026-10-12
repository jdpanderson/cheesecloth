# Windows

cheesecloth runs on Windows 10 and 11, as a service or in a console, with
userspace WireGuard on a Wintun adapter. `cheesecloth.exe` needs
`wintun.dll` for its architecture in the same folder; get it from
<https://www.wintun.net/>.

## The service

The same `cheesecloth daemon` command runs as a service when the service
manager starts it, and as a console daemon otherwise. To set up the service
by hand, from an elevated PowerShell, with `cheesecloth.exe` and
`wintun.dll` in `C:\Program Files\cheesecloth`:

```powershell
$exe = 'C:\Program Files\cheesecloth\cheesecloth.exe'
sc.exe create cheesecloth binPath= "`"$exe`" daemon" start= auto obj= LocalSystem
sc.exe failure cheesecloth reset= 86400 actions= restart/5000/restart/5000/restart/5000
sc.exe failureflag cheesecloth 1
$source = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\cheesecloth'
New-Item $source | Out-Null
New-ItemProperty $source EventMessageFile -PropertyType ExpandString -Value $exe | Out-Null
New-ItemProperty $source TypesSupported -PropertyType DWord -Value 7 | Out-Null
Start-Service cheesecloth
```

Put daemon options after `daemon` in `binPath=`. Test them in a console
first, with `cheesecloth daemon <options>`: the service cannot report an
error in its options (see [Weak points](#weak-points)).

Control the service from an elevated PowerShell:

```powershell
Start-Service cheesecloth
Stop-Service cheesecloth
Restart-Service cheesecloth
```

Stopping the service is clean: the daemon removes the WireGuard interface and
releases router port mappings, and the node stays in its cluster. The daemon
also stops cleanly when Windows shuts down. `cheesecloth stop` also stops the
service, and Windows does not restart it. With the failure actions above, if
the daemon crashes or fails, Windows restarts it after 5 seconds.

## Logs

The service logs to the Event Log: Event Viewer, **Windows Logs** >
**Application**, source `cheesecloth`. Or in PowerShell:

```powershell
Get-WinEvent -ProviderName cheesecloth -MaxEvents 20
```

`--log` sets the log filter, for example `--log cheesecloth_daemon=debug`. A
daemon run in a console logs to stdout.

## The CLI

The CLI works for administrators, in an elevated shell or not. Without
elevation it may do everything but `cheesecloth stop`; stop the service with
`Stop-Service cheesecloth` instead. Other users are refused. See
[the local API](LOCAL-API.md#access).

```powershell
cheesecloth init
cheesecloth status
```

The state directory is `C:\ProgramData\cheesecloth`. It holds the node's keys
and cluster state.

## Weak points

Windows lacks some things that other systems have, so these parts are weaker
there:

- **No directory sync.** Windows has no documented way to sync a directory.
  File data is still synced, but creating, renaming or removing a file is
  less durable after a power loss.
- **No NAT openers.** Windows limits raw sockets, so the raw UDP openers are
  not available and hole punching is weaker. More pairs of NATed peers need a
  port mapping, manual forwarding or a public endpoint, and their control
  messages go through relays.
- **UPnP only.** The port-mapping library cannot find the default gateway on
  Windows, so PCP and NAT-PMP do not work there; UPnP does.
- **Console stop.** A daemon run in a console stops cleanly on Ctrl-C or
  Ctrl-Break (or `cheesecloth stop`). It does not handle console close,
  log-off or system shutdown: Windows ends the process a few seconds after
  these, so a clean shutdown is not certain. The service stops cleanly at
  shutdown.
- **Access lists instead of modes.** The state directory, keys and state
  files allow only SYSTEM, Administrators and the daemon's user, with
  inheritance from the parent removed. Files the daemon creates in the
  directory inherit that list. If a user created the state directory before
  the daemon first ran and put files in it, those files keep their own access
  lists.
- **IPv4-mapped bind is IPv6-only.** A bind address like `::ffff:a.b.c.d` is
  IPv6-only on Windows. Only the unspecified address `[::]` is dual-stack.
- **Option errors under the service manager.** An error in the options (for
  example an unknown option) happens before the daemon can log anywhere. The
  service then just fails to start, with error 1067. Test options in a
  console first.
- **Events without text.** Event Viewer reads each event's text through the
  registered Event Log source. Without it, events show no text, and old
  events lose their text when the source is removed.
