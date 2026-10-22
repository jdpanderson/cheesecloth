use super::*;

#[tokio::test]
async fn port_zero_is_not_mapped() {
    let maps = PortMaps::start(0, 0);
    assert!(maps.wg.is_none() && maps.control.is_none());
    assert_eq!((maps.wg(), maps.control()), (None, None));
    assert!(maps.views().is_empty());
    tokio::time::timeout(std::time::Duration::from_millis(100), maps.stop())
        .await
        .expect("nothing to release");
}
