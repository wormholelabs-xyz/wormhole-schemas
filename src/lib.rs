#[cfg(feature = "fetch")]
pub(crate) mod fetch;
pub mod parse;
pub mod refs;
pub mod schema;
mod serialize;
#[cfg(feature = "fetch")]
pub mod sync;

pub mod registry;

pub use registry::Registry;
pub use schema::{FieldType, Schema};
pub use serialize::ArgInfo;

/// Return the persistent disk cache directory (if determinable).
#[cfg(feature = "fetch")]
pub fn cache_dir() -> Option<std::path::PathBuf> {
    fetch::cache_dir()
}
