use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use embednfs_proto::xdr::XdrEncode;
use embednfs_proto::{NFS_PROGRAM, NFS_V4, OpaqueAuth};

pub async fn send_rpc(stream: &mut TcpStream, xid: u32, proc_num: u32, payload: &[u8]) -> Bytes {
    send_rpc_with_auth(
        stream,
        xid,
        proc_num,
        payload,
        &OpaqueAuth::null(),
        &OpaqueAuth::null(),
    )
    .await
}

pub async fn send_rpc_with_auth(
    stream: &mut TcpStream,
    xid: u32,
    proc_num: u32,
    payload: &[u8],
    cred: &OpaqueAuth,
    verf: &OpaqueAuth,
) -> Bytes {
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

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let resp_len = (u32::from_be_bytes(header) & 0x7fff_ffff) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await.unwrap();
    Bytes::from(resp)
}
