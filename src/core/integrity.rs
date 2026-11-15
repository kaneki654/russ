use sha2::{Digest, Sha256};
use std::{io, path::Path};
use tokio::io::{AsyncRead, AsyncReadExt};

const HASH_BUFFER_BYTES: usize = 1024 * 1024;

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub async fn sha256_file(path: impl AsRef<Path>) -> io::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    sha256_reader(&mut file).await
}

pub async fn sha256_reader<R>(reader: &mut R) -> io::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub async fn verify_file_sha256(path: impl AsRef<Path>, expected: &str) -> io::Result<bool> {
    let actual = sha256_file(path).await?;
    Ok(actual.eq_ignore_ascii_case(expected.trim()))
}
