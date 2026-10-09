//! Where the login token is kept: one small file in the user's config folder.
//! The password is asked once (`ra-login`) and never stored.

use std::path::PathBuf;

fn path() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("dcload-ip-rs").join("retroachievements.token"))
}

/// `(user, token)` as saved by `ra-login`.
pub fn load() -> Option<(String, String)> {
    let text = std::fs::read_to_string(path()?).ok()?;
    let mut lines = text.lines();
    let user = lines.next()?.trim().to_string();
    let token = lines.next()?.trim().to_string();
    (!user.is_empty() && !token.is_empty()).then_some((user, token))
}

pub fn save(user: &str, token: &str) -> std::io::Result<PathBuf> {
    let p = path().ok_or_else(|| std::io::Error::other("no config folder (APPDATA, HOME)"))?;
    std::fs::create_dir_all(p.parent().unwrap())?;
    std::fs::write(&p, format!("{user}\n{token}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(p)
}
