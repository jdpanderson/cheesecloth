//! macOS: userspace WireGuard on a utun device. macOS has no kernel
//! WireGuard.

use std::{io, net::Ipv4Addr};

use anyhow::{Result, bail};
use ipnet::IpNet;

use super::{Platform, unix};
use crate::{Backend, InterfaceConfig};

pub(crate) struct MacOs;

impl Platform for MacOs {
    // macOS only allows utun interfaces for userspace tunnels.
    const DEFAULT_INTERFACE: &'static str = "utun77";
    const KERNEL_WIREGUARD: bool = false;

    fn open_kernel(_config: &InterfaceConfig) -> Result<Box<dyn Backend>> {
        bail!("macOS has no kernel WireGuard")
    }

    fn remove_kernel(_name: &str) -> Result<()> {
        bail!("macOS has no kernel WireGuard")
    }

    fn create_tun(name: &str, addresses: &[IpNet], mtu: u16) -> Result<tun_rs::AsyncDevice> {
        // A utun device is point-to-point.
        unix::create_p2p_tun(name, addresses, mtu)
    }

    fn interface_exists(name: &str) -> Result<bool> {
        Ok(unix::interface_index(name)?.is_some())
    }

    fn send_raw_udp(dst: Ipv4Addr, segment: &[u8]) -> io::Result<()> {
        unix::send_raw_udp(dst, segment)
    }
}
