use super::manifest::validate_relative_path;
use std::{
    io,
    path::{Path, PathBuf},
};

/// Destination validation shared by the network receiver and local recovery
/// code. It never accepts a path supplied by a peer directly.
pub fn safe_destination(root: impl AsRef<Path>, relative_path: &Path) -> io::Result<PathBuf> {
    let relative = validate_relative_path(relative_path)?;
    let root = root.as_ref().canonicalize().or_else(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            std::fs::create_dir_all(root.as_ref())?;
            root.as_ref().canonicalize()
        } else {
            Err(error)
        }
    })?;
    let destination = root.join(relative);
    if !destination.starts_with(&root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "destination escapes receive root",
        ));
    }
    Ok(destination)
}
