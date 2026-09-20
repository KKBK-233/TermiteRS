use serde::Serialize;

pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncommit: ",
    env!("TERMITE_GIT_SHA"),
    "\nbuilt: ",
    env!("TERMITE_BUILD_UNIX")
);

#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub version: &'static str,
    pub git_sha: &'static str,
    pub build_unix: &'static str,
}

pub fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
        git_sha: env!("TERMITE_GIT_SHA"),
        build_unix: env!("TERMITE_BUILD_UNIX"),
    }
}
