//! Puts a message table and app icon in cheesecloth.exe on Windows. The Event
//! Log source "cheesecloth" names the exe as its message file, and Event
//! Viewer uses message 1 (`%1`) to show the text of each event. The build
//! writes the .res file itself, so it needs no Windows SDK tools.

use std::{env, fs, path::PathBuf};

/// The message that shows its insert string. The daemon's
/// `service/windows/event_log.rs` and `tests/cli.rs` use the same ID.
const MESSAGE_ID: u32 = 1;

/// The resource type of a message table.
const RT_MESSAGETABLE: u16 = 11;
const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=resources/AppIcon.ico");
    let target = |key: &str| env::var(key).unwrap_or_default();
    if target("CARGO_CFG_TARGET_OS") != "windows" || target("CARGO_CFG_TARGET_ENV") != "msvc" {
        return;
    }
    let res = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("messages.res");
    fs::write(&res, resource_file()).expect("writing messages.res");
    // link.exe and lld-link both take a .res file as an input.
    println!("cargo:rustc-link-arg-bins={}", res.display());
}

/// A .res file that holds the message table and app icon.
fn resource_file() -> Vec<u8> {
    let mut res = Vec::new();
    // Every .res file starts with an empty entry.
    resource(&mut res, 0, 0, 0, 0, &[]);
    // Moveable, pure and discardable; English (United States).
    resource(
        &mut res,
        RT_MESSAGETABLE,
        1,
        0x1030,
        0x0409,
        &message_table(),
    );
    icon_resources(&mut res);
    res
}

/// Adds each image from the ICO, followed by the group that makes them one icon.
fn icon_resources(res: &mut Vec<u8>) {
    let icon = include_bytes!("resources/AppIcon.ico");
    assert_eq!(&icon[..4], &[0, 0, 1, 0], "invalid ICO header");
    let count = u16::from_le_bytes([icon[4], icon[5]]) as usize;
    assert!(count > 0, "ICO has no images");
    let mut group = icon[..6].to_vec();

    for index in 0..count {
        let start = 6 + index * 16;
        let entry = icon
            .get(start..start + 16)
            .expect("incomplete ICO directory");
        let size = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(entry[12..16].try_into().unwrap()) as usize;
        let image = icon
            .get(offset..offset + size)
            .expect("incomplete ICO image");
        let id = u16::try_from(index + 1).unwrap();
        resource(res, RT_ICON, id, 0x1030, 0x0409, image);
        group.extend_from_slice(&entry[..12]);
        group.extend_from_slice(&id.to_le_bytes());
    }

    resource(res, RT_GROUP_ICON, 1, 0x1030, 0x0409, &group);
}

/// Adds one resource with an ID for its type and name.
fn resource(res: &mut Vec<u8>, kind: u16, name: u16, flags: u16, language: u16, data: &[u8]) {
    const HEADER_SIZE: u32 = 32;
    res.extend((data.len() as u32).to_le_bytes());
    res.extend(HEADER_SIZE.to_le_bytes());
    for word in [0xFFFF, kind, 0xFFFF, name] {
        res.extend(word.to_le_bytes());
    }
    res.extend(0u32.to_le_bytes()); // data version
    res.extend(flags.to_le_bytes());
    res.extend(language.to_le_bytes());
    res.extend(0u64.to_le_bytes()); // version and characteristics
    res.extend(data);
    pad(res);
}

/// A MESSAGE_RESOURCE_DATA with one block that holds message `MESSAGE_ID`.
fn message_table() -> Vec<u8> {
    let mut text: Vec<u8> = "%1\r\n\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    pad(&mut text);
    let mut table = Vec::new();
    // One block: its lowest and highest ID, and where its entries start.
    for value in [1, MESSAGE_ID, MESSAGE_ID, 16] {
        table.extend(value.to_le_bytes());
    }
    // The entry: its length with this 4-byte header, then flags 1 (UTF-16).
    table.extend((4 + text.len() as u16).to_le_bytes());
    table.extend(1u16.to_le_bytes());
    table.extend(text);
    table
}

/// Pads `bytes` with zeros to a multiple of 4.
fn pad(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}
