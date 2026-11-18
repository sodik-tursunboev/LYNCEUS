//! A native window around the Lynceus console.
//!
//! It shows the console that the core already serves at http://127.0.0.1:<port>/console/. It makes sure
//! the agent (which runs the core) is running, asks it for the signed-in address (`Lynceus.Agent.exe
//! --console-link`, so the API token is only ever handled by the agent), and points the window there.
//! It talks to nothing else: no network code other than one loopback health check, and the window may
//! only navigate to this machine. The console page gets no access to the shell (no commands, no
//! capabilities are granted).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tauri::{WebviewUrl, WebviewWindow, WebviewWindowBuilder};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;
const START_WAIT: Duration = Duration::from_secs(60);

/// `<install>\shell\lynceus-console.exe` sits next to `<install>\agent\Lynceus.Agent.exe`.
fn agent_exe() -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("LYNCEUS_AGENT_EXE") {
        return Ok(PathBuf::from(p)); // development builds only
    }
    let here = std::env::current_exe().map_err(|e| e.to_string())?;
    let agent = here
        .parent()
        .and_then(|shell| shell.parent())
        .map(|install| install.join("agent").join("Lynceus.Agent.exe"))
        .ok_or("cannot find the install folder")?;
    if agent.is_file() {
        Ok(agent)
    } else {
        Err(format!("the Lynceus agent was not found at {}", agent.display()))
    }
}

/// `http://127.0.0.1:<port>/console/#code=<one-time code>`, exactly this shape and nothing else. Returns the
/// port. Since H1 the agent hands out a one-time code, never the API token, and the console accepts only a
/// code of 16 to 128 letters, digits, `_` or `-` (console/src/auth.ts); the same rule applies here.
fn check_link(link: &str) -> Result<u16, String> {
    let rest = link
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| link.strip_prefix("http://localhost:"))
        .ok_or("the console address is not on this machine")?;
    let (port, tail) = rest.split_once('/').ok_or("the console address is malformed")?;
    let port: u16 = port.parse().map_err(|_| "the console address has no valid port")?;
    let code = tail
        .strip_prefix("console/#code=")
        .ok_or("the console address is malformed")?;
    let ok = (16..=128).contains(&code.len())
        && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if port == 0 || !ok {
        return Err("the console address is malformed".into());
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::check_link;

    #[test]
    fn accepts_the_agents_one_time_code_link() {
        let code = "k2l-FKOrgbefTJES3Itb3-GzD4obrVF_oOyPXtQcuAg"; // pragma: allowlist secret
        assert_eq!(check_link(&format!("http://127.0.0.1:8765/console/#code={code}")), Ok(8765));
        assert_eq!(check_link(&format!("http://localhost:9000/console/#code={code}")), Ok(9000));
    }

    #[test]
    fn refuses_a_token_link_and_anything_else() {
        let long = "a".repeat(129);
        for bad in [
            "http://127.0.0.1:8765/console/#token=abcdefghijklmnopqrstuvwx", // the pre-H1 form: a token in the address
            "http://evil.test:8765/console/#code=abcdefghijklmnopqrstuvwx",
            "http://127.0.0.1:8765/console/#code=short",
            "http://127.0.0.1:8765/console/#code=has+plus/slash=abcdefghijk",
            "http://127.0.0.1:0/console/#code=abcdefghijklmnopqrstuvwx",
            "http://127.0.0.1:8765/other/#code=abcdefghijklmnopqrstuvwx",
            &format!("http://127.0.0.1:8765/console/#code={long}"),
        ] {
            assert!(check_link(bad).is_err(), "accepted {bad}");
        }
    }
}

fn console_link(agent: &PathBuf) -> Result<(String, u16), String> {
    let out = Command::new(agent)
        .arg("--console-link")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("could not run the agent: {e}"))?;
    if !out.status.success() {
        return Err("the agent could not build the console address (see agent.log)".into());
    }
    let link = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let port = check_link(&link)?;
    Ok((link, port))
}

/// One loopback request to the core's open `/health` route.
fn healthy(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let request = format!("GET /health HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if s.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut reply = String::new();
    let _ = (&s).take(4096).read_to_string(&mut reply);
    reply.starts_with("HTTP/1.1 200") || reply.starts_with("HTTP/1.0 200")
}

/// The agent keeps running after this window closes. Starting it twice is harmless (it is one per user).
fn start_agent(agent: &PathBuf) -> Result<(), String> {
    Command::new(agent)
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not start the agent: {e}"))
}

/// Text for the loading page, set as text (never as markup).
fn say(window: &WebviewWindow, text: &str, problem: bool) {
    let escaped: String = text
        .chars()
        .flat_map(|c| match c {
            '\\' => vec!['\\', '\\'],
            '\'' => vec!['\\', '\''],
            '\n' | '\r' => vec![' '],
            c => vec![c],
        })
        .collect();
    let _ = window.eval(format!(
        "(function(){{var m=document.getElementById('msg');if(m){{m.textContent='{escaped}';}}\
         document.body.classList.toggle('problem',{problem});}})()"
    ));
}

fn launch(window: WebviewWindow) {
    let result = (|| -> Result<String, String> {
        let agent = agent_exe()?;
        let (link, port) = console_link(&agent)?;
        if !healthy(port) {
            say(&window, "Starting Lynceus\u{2026}", false);
            start_agent(&agent)?;
            let deadline = Instant::now() + START_WAIT;
            while !healthy(port) {
                if Instant::now() > deadline {
                    return Err("The Lynceus core did not answer within a minute. Look at agent.log and core.log in %LOCALAPPDATA%\\Lynceus.".into());
                }
                thread::sleep(Duration::from_millis(500));
            }
        }
        Ok(link)
    })();
    match result {
        // the link was checked: only [A-Za-z0-9:/#._+=-] can be in it, so it is safe inside quotes
        Ok(link) => {
            let _ = window.eval(format!("window.location.replace('{link}')"));
        }
        Err(e) => say(&window, &e, true),
    }
}

/// The window may show this machine's console and its own loading page, nothing else.
fn allowed_navigation(url: &tauri::Url) -> bool {
    matches!(url.scheme(), "http" | "https" | "tauri")
        && matches!(
            url.host_str(),
            Some("127.0.0.1") | Some("localhost") | Some("tauri.localhost")
        )
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let window = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Lynceus")
                .inner_size(1320.0, 860.0)
                .min_inner_size(960.0, 640.0)
                .center()
                .on_navigation(allowed_navigation)
                .build()?;
            thread::spawn(move || launch(window));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the Lynceus console window failed to start");
}
