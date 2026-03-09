use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tokio::sync::oneshot;

use embednfs::{FileSystem, MemFs, NfsServer};

pub struct ExternalServerHandle {
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl ExternalServerHandle {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for ExternalServerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn start_external_server() -> ExternalServerHandle {
    start_external_server_with_fs(MemFs::new())
}

pub fn start_external_server_with_fs<F: FileSystem>(fs: F) -> ExternalServerHandle {
    let (port_tx, port_rx) = mpsc::sync_channel(1);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let thread = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = NfsServer::new(fs);
            let server_task = tokio::spawn(async move {
                server.serve(listener).await.unwrap();
            });

            port_tx.send(port).unwrap();
            let _ = shutdown_rx.await;
            server_task.abort();
            let _ = server_task.await;
        });
    });

    let port = port_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    ExternalServerHandle {
        port,
        shutdown: Some(shutdown_tx),
        thread: Some(thread),
    }
}
