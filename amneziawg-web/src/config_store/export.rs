// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

//! Shared bounded export reader for authenticated and email delivery routes.
//! The configured directory and its ancestors must be administrator-controlled.
use std::{
    io,
    path::{Component, Path},
};
use tokio::io::AsyncReadExt;

pub const MAX_EXPORT_BYTES: usize = 256 * 1024;

pub async fn read_config(directory: &Path, path: &Path) -> io::Result<String> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid export path");
    if path.extension().and_then(|v| v.to_str()) != Some("conf")
        || path
            .components()
            .any(|v| matches!(v, Component::ParentDir | Component::CurDir))
        || tokio::fs::symlink_metadata(path)
            .await?
            .file_type()
            .is_symlink()
    {
        return Err(invalid());
    }
    let directory = tokio::fs::canonicalize(directory).await?;
    let path = tokio::fs::canonicalize(path).await?;
    // Config discovery is non-recursive; exports share that boundary.
    if path.parent() != Some(directory.as_path()) {
        return Err(invalid());
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path).await?;
    if !file.metadata().await?.is_file() {
        return Err(invalid());
    }
    let mut text = String::new();
    file.take((MAX_EXPORT_BYTES + 1) as u64)
        .read_to_string(&mut text)
        .await?;
    if text.len() > MAX_EXPORT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "export exceeds size limit",
        ));
    }
    Ok(text)
}
