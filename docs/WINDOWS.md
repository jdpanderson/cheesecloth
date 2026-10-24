# Windows

Cheesecloth runs on Windows 10 and 11, as a service or in a console. It uses
userspace WireGuard on a Wintun adapter, so `cheesecloth.exe` needs
`wintun.dll` for its architecture in the same folder. Get it from
<https://www.wintun.net/>.

The installer from
[cheesecloth-windows](https://github.com/jdpanderson/cheesecloth-windows) sets
all of this up. This page is for setting it up by hand.

## The service

`cheesecloth daemon` runs as a service when Windows starts it, and as a
console program otherwise.

Put `cheesecloth.exe` and `wintun.dll` in a folder that only administrators
can change, such as `C:\Program Files\cheesecloth`. The service runs as
LocalSystem, so anyone who can change that folder can take over the machine.
A new folder under `C:\` may let every user change it.

Then, from an elevated PowerShell:

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

This makes Windows restart the daemon 5 seconds after a crash, and registers
it with the Event Log.

To add daemon options, put them after `daemon` in `binPath=`. Test them first
with `cheesecloth daemon <options>` in a console. If an option is wrong, the
service only fails with error 1067, and logs nothing.

Use `Start-Service`, `Stop-Service` and `Restart-Service cheesecloth` to
control it. A stop removes the WireGuard interface and releases router port
mappings, and the node stays in its cluster. `cheesecloth stop` also stops
the service, and Windows does not restart it.

## Logs

The service logs to the Event Log, under **Windows Logs** > **Application**,
source `cheesecloth`. In PowerShell:

```powershell
Get-WinEvent -ProviderName cheesecloth -MaxEvents 20
```

`--log` sets the filter, such as `--log cheesecloth_daemon=debug`. In a
console, the daemon logs to the screen.

## The CLI

Administrators can use the CLI, elevated or not. Without elevation, they can
do everything except `cheesecloth stop`. Other users can't use it. See
[the local API](LOCAL-API.md#access).

State is in `C:\ProgramData\cheesecloth`. It holds the node's keys and
cluster state.

## Weak points

These parts are weaker on Windows than elsewhere:

- **Disk sync.** Windows can't sync a directory. After a power loss, a file
  that was just made, renamed or removed may be lost.
- **NAT hole punching.** Windows limits raw sockets, so Cheesecloth can't send
  NAT openers. More peers behind NAT need a port mapping, a forwarded port or
  a public address, and their control messages go through relays.
- **UPnP only.** PCP and NAT-PMP don't work, because the port-mapping library
  can't find the gateway on Windows.
- **Console stop.** In a console, Ctrl-C, Ctrl-Break and `cheesecloth stop`
  stop the daemon cleanly. Closing the window, logging off or shutting down
  may not. The service always stops cleanly.
- **File access.** Only SYSTEM, Administrators and the daemon's user can read
  the state. Files that a user put in the state directory before the daemon
  first ran keep their own access.
- **IPv4-mapped addresses.** Binding to `::ffff:a.b.c.d` is IPv6-only. Only
  `[::]` accepts both IPv4 and IPv6.
- **Event text.** Event Viewer needs the registered source to show event
  text. If you remove it, old events lose their text too.
