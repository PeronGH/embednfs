use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

static NFS4J_JAR: OnceLock<Result<PathBuf, String>> = OnceLock::new();

const NFS4J_MAIN_CLASS: &str = "org.dcache.nfs.v4.client.EmbednfsHarness";

#[derive(Debug)]
pub struct HarnessOutput {
    pub stdout: String,
    pub stderr: String,
}

pub fn ensure_nfs4j_jar() -> Result<PathBuf, String> {
    NFS4J_JAR.get_or_init(resolve_nfs4j_jar).clone()
}

pub fn run_nfs4j_harness(mode: &str, port: u16, timeout: Duration) -> Result<HarnessOutput, String> {
    let jar = ensure_nfs4j_jar()?;
    let mut child = Command::new("java")
        .arg("-cp")
        .arg(&jar)
        .arg(NFS4J_MAIN_CLASS)
        .arg(mode)
        .args(["--host", "127.0.0.1"])
        .args(["--port", &port.to_string()])
        .args(["--export", "/"])
        .args(["--pnfs", "off"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn nfs4j harness: {e}"))?;

    let start = Instant::now();
    loop {
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .map_err(|e| format!("failed to collect timed-out harness output: {e}"))?;
            return Err(format!(
                "nfs4j {mode} timed out after {:?}\nstdout:\n{}\nstderr:\n{}",
                timeout,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|e| format!("failed to collect nfs4j harness output: {e}"))?;
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                if status.success() {
                    return Ok(HarnessOutput { stdout, stderr });
                }
                return Err(format!(
                    "nfs4j {mode} exited with {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("failed to poll nfs4j harness: {e}")),
        }
    }
}

fn resolve_nfs4j_jar() -> Result<PathBuf, String> {
    let root = workspace_root()?;
    let script = root.join("scripts/ensure-nfs4j-client.sh");
    if !script.is_file() {
        return Err(format!("missing nfs4j bootstrap script at {}", script.display()));
    }

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .map_err(|e| format!("failed to run {}: {e}", script.display()))?;

    if !output.status.success() {
        return Err(format!(
            "failed to build pinned nfs4j harness via {}\nstdout:\n{}\nstderr:\n{}",
            script.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let jar = String::from_utf8(output.stdout)
        .map_err(|e| format!("nfs4j bootstrap script returned non-utf8 output: {e}"))?;
    let jar = jar.trim();
    if jar.is_empty() {
        return Err("nfs4j bootstrap script did not return a jar path".to_string());
    }

    let jar = PathBuf::from(jar);
    if !jar.is_file() {
        return Err(format!("nfs4j jar path does not exist: {}", jar.display()));
    }
    Ok(jar)
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|e| format!("failed to resolve workspace root: {e}"))
}
