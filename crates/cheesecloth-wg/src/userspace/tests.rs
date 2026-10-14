use super::*;

/// An IP side that sends nowhere and receives nothing: the test uses only
/// GotaTun's peers, so it needs no TUN device and no privileges.
#[derive(Clone)]
struct NoIp;

impl IpSend for NoIp {
    async fn send(&mut self, _packet: Packet<Ip>) -> io::Result<()> {
        Ok(())
    }
}

impl IpRecv for NoIp {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        std::future::pending::<io::Result<iter::Empty<Packet<Ip>>>>().await
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1420)
    }
}

type TestDevice = Device<(UdpSocketFactory, NoIp, NoIp)>;

fn peer(key: u8, endpoint: Option<&str>, keepalive: Option<u16>, allowed_ip: &str) -> Peer {
    let mut peer = Peer::new(PublicKey::from([key; 32]));
    peer.endpoint = endpoint.map(|e| e.parse().unwrap());
    peer.keepalive = keepalive;
    peer.allowed_ips = vec![allowed_ip.parse().unwrap()];
    peer
}

async fn current(device: &TestDevice, key: u8) -> Peer {
    device
        .peers()
        .await
        .into_iter()
        .map(|stats| stats.peer)
        .find(|peer| peer.public_key == PublicKey::from([key; 32]))
        .expect("the peer exists")
}

#[tokio::test]
async fn an_update_without_an_endpoint_keeps_the_one_the_peer_has() -> Result<()> {
    // Peers need the device's key, which binds a UDP port.
    let mut device = DeviceBuilder::new()
        .with_default_udp()
        .with_ip(NoIp)
        .with_listen_port(0)
        .with_private_key(StaticSecret::from([9; 32]))
        .build()
        .await?;
    set_peer(
        &mut device,
        peer(1, Some("192.0.2.10:51820"), None, "100.64.0.2/32"),
    )
    .await?;

    // The other fields change, and the endpoint stays.
    set_peer(&mut device, peer(1, None, Some(25), "100.64.0.3/32")).await?;
    let changed = current(&device, 1).await;
    assert_eq!(changed.endpoint, Some("192.0.2.10:51820".parse()?));
    assert_eq!(changed.keepalive, Some(25));
    assert_eq!(
        changed.allowed_ips,
        vec!["100.64.0.3/32".parse::<IpNetwork>()?]
    );

    // A new endpoint replaces it.
    set_peer(
        &mut device,
        peer(1, Some("192.0.2.11:51820"), Some(25), "100.64.0.3/32"),
    )
    .await?;
    assert_eq!(
        current(&device, 1).await.endpoint,
        Some("192.0.2.11:51820".parse()?)
    );

    // A new peer without one has none.
    set_peer(&mut device, peer(2, None, None, "100.64.0.4/32")).await?;
    assert_eq!(current(&device, 2).await.endpoint, None);
    device.stop().await;
    Ok(())
}
