use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use embednfs_proto::xdr::XdrEncode;
use embednfs_proto::{NFS_PROGRAM, NFS_V4, OpaqueAuth};

pub async fn send_rpc(stream: &mut TcpStream, xid: u32, proc_num: u32, payload: &[u8]) -> Bytes {
    send_rpc_record(stream, xid, proc_num, payload).await.0
}

pub async fn send_rpc_record(
    stream: &mut TcpStream,
    xid: u32,
    proc_num: u32,
    payload: &[u8],
) -> (Bytes, usize) {
    send_rpc_record_with_auth(
        stream,
        xid,
        proc_num,
        payload,
        &OpaqueAuth::null(),
        &OpaqueAuth::null(),
    )
    .await
}

pub async fn send_rpc_record_with_auth(
    stream: &mut TcpStream,
    xid: u32,
    proc_num: u32,
    payload: &[u8],
    cred: &OpaqueAuth,
    verf: &OpaqueAuth,
) -> (Bytes, usize) {
    let mut msg = BytesMut::with_capacity(256);
    xid.encode(&mut msg);
    0u32.encode(&mut msg);
    2u32.encode(&mut msg);
    NFS_PROGRAM.encode(&mut msg);
    NFS_V4.encode(&mut msg);
    proc_num.encode(&mut msg);
    cred.encode(&mut msg);
    verf.encode(&mut msg);
    msg.put_slice(payload);

    let len = msg.len() as u32 | 0x8000_0000;
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(&msg).await.unwrap();
    stream.flush().await.unwrap();

    let mut resp = BytesMut::new();
    let mut fragment_count = 0usize;
    loop {
        let mut header = [0u8; 4];
        let _ = stream.read_exact(&mut header).await.unwrap();
        let header_val = u32::from_be_bytes(header);
        let last_fragment = (header_val & 0x8000_0000) != 0;
        let resp_len = (header_val & 0x7fff_ffff) as usize;
        let offset = resp.len();
        resp.resize(offset + resp_len, 0);
        let _ = stream.read_exact(&mut resp[offset..]).await.unwrap();
        fragment_count += 1;
        if last_fragment {
            break;
        }
    }
    (resp.freeze(), fragment_count)
}

pub async fn send_rpc_with_auth(
    stream: &mut TcpStream,
    xid: u32,
    proc_num: u32,
    payload: &[u8],
    cred: &OpaqueAuth,
    verf: &OpaqueAuth,
) -> Bytes {
    send_rpc_record_with_auth(stream, xid, proc_num, payload, cred, verf)
        .await
        .0
}
