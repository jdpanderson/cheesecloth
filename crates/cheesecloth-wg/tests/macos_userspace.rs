//! Real utun and encrypted packet tests. Run only on a disposable Mac with root.
#![cfg(target_os = "macos")]

mod common;

use anyhow::{Context, Result, ensure};
use cheesecloth_wg::BackendKind;
use common::*;

#[test]
fn real_userspace_tunnel() -> Result<()> {
    ensure!(is_root(), "this test requires root");
    let dns_before = dns_settings()?;
    let name = (200..256)
        .map(|i| format!("utun{i}"))
        .find(|name| !interface_exists(name))
        .context("no unused test interface")?;
    let (config, peer, remote) = tunnel_setup(&name)?;

    // Reuse the same name and addresses to catch leaked interfaces or routes.
    for kind in [BackendKind::Auto, BackendKind::Userspace] {
        println!("checking {kind:?} on {name}");
        let mut interface = Interface(cheesecloth_wg::open(kind, &config)?);
        let backend = &mut interface.0;
        ensure!(backend.kind() == "userspace", "wrong backend selected");
        ensure!(
            command("/sbin/ifconfig", &[&name])?.contains("mtu 1280"),
            "MTU was not applied"
        );
        for address in [REMOTE_V4, REMOTE_V6] {
            ensure!(
                route_interface(address)? == name,
                "missing route to {address}"
            );
        }
        exercise_peer(backend.as_mut(), &peer)?;
        backend.down().context("removing the interface")?;
        backend.down().context("repeating interface removal")?;
        ensure!(!interface_exists(&name), "interface survived removal");
        ensure!(
            !command("/usr/sbin/netstat", &["-rn"])?
                .split_whitespace()
                .any(|field| field == name),
            "route survived removal"
        );
        cheesecloth_wg::remove_existing(BackendKind::Userspace, &name)?;
    }
    remote.finish()?;
    check_nat_opener()?;
    ensure!(dns_settings()? == dns_before, "DNS settings changed");
    Ok(())
}

#[allow(unsafe_code, reason = "the standard library has no geteuid")]
fn is_root() -> bool {
    // SAFETY: geteuid has no arguments or side effects.
    unsafe { libc::geteuid() == 0 }
}

fn route_interface(address: &str) -> Result<String> {
    let family = if address.contains(':') {
        "-inet6"
    } else {
        "-inet"
    };
    command("/sbin/route", &["-n", "get", family, address])?
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("interface:")
                .map(|s| s.trim().to_owned())
        })
        .context("route has no interface")
}

fn dns_settings() -> Result<Vec<String>> {
    let services = command("/usr/sbin/networksetup", &["-listallnetworkservices"])?;
    let mut settings = Vec::new();
    for service in services.lines().skip(1) {
        let service = service.trim_start_matches('*');
        settings.push(service.to_owned());
        for flag in ["-getdnsservers", "-getsearchdomains"] {
            settings.push(command("/usr/sbin/networksetup", &[flag, service])?);
        }
    }
    Ok(settings)
}
