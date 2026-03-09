use bytes::{Buf, BytesMut};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

use embednfs::MemFs;
use embednfs_proto::xdr::*;
use embednfs_proto::*;

const RPC_LAST_FRAGMENT: u32 = 0x8000_0000;

/// Send a raw RPC message over TCP and receive the response.
async fn rpc_roundtrip(stream: &mut TcpStream, rpc_data: &[u8]) -> Vec<u8> {
    let frag_header = (rpc_data.len() as u32) | RPC_LAST_FRAGMENT;
    stream
        .write_all(&frag_header.to_be_bytes())
        .await
        .unwrap();
    stream.write_all(rpc_data).await.unwrap();
    stream.flush().await.unwrap();

    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await.unwrap();
    let resp_val = u32::from_be_bytes(resp_header);
    let resp_len = (resp_val & !RPC_LAST_FRAGMENT) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await.unwrap();
    resp
}

/// Build a raw RPC COMPOUND request with AUTH_NONE.
fn build_rpc_compound(compound_body: &[u8]) -> Vec<u8> {
    let mut raw = BytesMut::with_capacity(64 + compound_body.len());
    1u32.encode(&mut raw); // xid
    0u32.encode(&mut raw); // msg type = call
    2u32.encode(&mut raw); // rpc version
    100003u32.encode(&mut raw); // program = NFS
    4u32.encode(&mut raw); // version
    1u32.encode(&mut raw); // procedure = COMPOUND
    0u32.encode(&mut raw); // cred flavor = AUTH_NONE
    encode_opaque(&mut raw, &[]); // cred body
    0u32.encode(&mut raw); // verf flavor = AUTH_NONE
    encode_opaque(&mut raw, &[]); // verf body
    raw.extend_from_slice(compound_body);
    raw.to_vec()
}

fn build_exchange_id(owner: &[u8]) -> Vec<u8> {
    let mut body = BytesMut::with_capacity(128);
    encode_opaque(&mut body, &[]); // tag
    1u32.encode(&mut body); // minorversion
    1u32.encode(&mut body); // op count
    OP_EXCHANGE_ID.encode(&mut body);
    body.extend_from_slice(&[0u8; 8]); // verifier (fixed 8)
    encode_opaque(&mut body, owner); // ownerid
    (EXCHGID4_FLAG_USE_NON_PNFS as u32).encode(&mut body);
    0u32.encode(&mut body); // SP4_NONE
    0u32.encode(&mut body); // impl_id count = 0
    body.to_vec()
}

fn build_create_session(clientid: u64) -> Vec<u8> {
    let mut body = BytesMut::with_capacity(256);
    encode_opaque(&mut body, &[]); // tag
    1u32.encode(&mut body); // minorversion
    1u32.encode(&mut body); // op count
    OP_CREATE_SESSION.encode(&mut body);
    clientid.encode(&mut body);
    1u32.encode(&mut body); // sequence
    0u32.encode(&mut body); // flags
    // fore_chan_attrs
    0u32.encode(&mut body);
    (1024 * 1024u32).encode(&mut body);
    (1024 * 1024u32).encode(&mut body);
    (1024 * 1024u32).encode(&mut body);
    64u32.encode(&mut body);
    64u32.encode(&mut body);
    0u32.encode(&mut body);
    // back_chan_attrs
    0u32.encode(&mut body);
    (1024 * 1024u32).encode(&mut body);
    (1024 * 1024u32).encode(&mut body);
    (1024 * 1024u32).encode(&mut body);
    64u32.encode(&mut body);
    64u32.encode(&mut body);
    0u32.encode(&mut body);
    0x40000000u32.encode(&mut body); // cb_program
    1u32.encode(&mut body); // sec_parms count
    0u32.encode(&mut body); // AUTH_NONE
    body.to_vec()
}

fn build_sequence_putrootfh_getattr(sessionid: &[u8; 16], seqid: u32) -> Vec<u8> {
    let mut body = BytesMut::with_capacity(128);
    encode_opaque(&mut body, &[]); // tag
    1u32.encode(&mut body);
    3u32.encode(&mut body);
    OP_SEQUENCE.encode(&mut body);
    body.extend_from_slice(sessionid);
    seqid.encode(&mut body);
    0u32.encode(&mut body); // slotid
    63u32.encode(&mut body);
    0u32.encode(&mut body); // cachethis
    OP_PUTROOTFH.encode(&mut body);
    OP_GETATTR.encode(&mut body);
    let mut bm = Bitmap4::new();
    bm.set(FATTR4_TYPE);
    bm.set(FATTR4_SIZE);
    bm.set(FATTR4_FILEID);
    bm.encode(&mut body);
    body.to_vec()
}

fn build_sequence_putrootfh_getfh(sessionid: &[u8; 16], seqid: u32) -> Vec<u8> {
    let mut body = BytesMut::with_capacity(128);
    encode_opaque(&mut body, &[]);
    1u32.encode(&mut body);
    3u32.encode(&mut body);
    OP_SEQUENCE.encode(&mut body);
    body.extend_from_slice(sessionid);
    seqid.encode(&mut body);
    0u32.encode(&mut body);
    63u32.encode(&mut body);
    0u32.encode(&mut body);
    OP_PUTROOTFH.encode(&mut body);
    OP_GETFH.encode(&mut body);
    body.to_vec()
}

struct SessionSetup {
    sessionid: [u8; 16],
    #[expect(dead_code)]
    root_fh: Vec<u8>,
}

async fn setup_session(stream: &mut TcpStream) -> SessionSetup {
    // EXCHANGE_ID
    let body = build_exchange_id(b"bench-client");
    let rpc = build_rpc_compound(&body);
    let resp = rpc_roundtrip(stream, &rpc).await;
    let mut src = bytes::Bytes::from(resp);
    // Skip RPC reply: xid(4) + type(4) + stat(4) + verf_flavor(4) + verf_len(4) + accept_stat(4)
    src.advance(4 + 4 + 4 + 4 + 4 + 4);
    // Compound4Res: status(4) + tag_len(4) + rescount(4)
    src.advance(4 + 4 + 4);
    // EXCHANGE_ID result: opnum(4) + status(4) + clientid(8)
    src.advance(4 + 4);
    let clientid = src.get_u64();

    // CREATE_SESSION
    let body = build_create_session(clientid);
    let rpc = build_rpc_compound(&body);
    let resp = rpc_roundtrip(stream, &rpc).await;
    let mut src = bytes::Bytes::from(resp);
    src.advance(4 + 4 + 4 + 4 + 4 + 4); // RPC reply
    src.advance(4 + 4 + 4); // Compound header
    src.advance(4 + 4); // opnum + status
    let mut sessionid = [0u8; 16];
    sessionid.copy_from_slice(&src[..16]);
    src.advance(16);

    // SEQUENCE + PUTROOTFH + GETFH
    let body = build_sequence_putrootfh_getfh(&sessionid, 1);
    let rpc = build_rpc_compound(&body);
    let resp = rpc_roundtrip(stream, &rpc).await;
    let mut src = bytes::Bytes::from(resp);
    src.advance(4 + 4 + 4 + 4 + 4 + 4); // RPC reply
    src.advance(4 + 4 + 4); // Compound header
    // SEQUENCE: opnum(4) + status(4) + sessionid(16) + seqid(4) + slotid(4) + highest(4) + target(4) + flags(4)
    src.advance(4 + 4 + 16 + 4 + 4 + 4 + 4 + 4);
    // PUTROOTFH: opnum(4) + status(4)
    src.advance(4 + 4);
    // GETFH: opnum(4) + status(4) + fh
    src.advance(4 + 4);
    let fh_len = src.get_u32() as usize;
    let root_fh = src[..fh_len].to_vec();

    SessionSetup {
        sessionid,
        root_fh,
    }
}

fn bench_tcp_round_trip(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let memfs = MemFs::new();
    let server = embednfs::NfsServer::new(memfs);
    rt.spawn(async move {
        let _ = server.serve(listener).await;
    });

    let mut stream = rt.block_on(TcpStream::connect(addr)).unwrap();
    let _ = rt.block_on(async { stream.set_nodelay(true) });

    let setup = rt.block_on(setup_session(&mut stream));

    let mut group = c.benchmark_group("tcp_round_trip");

    // SEQUENCE + PUTROOTFH + GETATTR
    {
        let mut seqid = 2u32;
        group.bench_function("sequence_putrootfh_getattr", |b| {
            b.iter(|| {
                let body = build_sequence_putrootfh_getattr(&setup.sessionid, seqid);
                let rpc = build_rpc_compound(&body);
                let resp = rt.block_on(rpc_roundtrip(&mut stream, &rpc));
                black_box(resp);
                seqid = seqid.wrapping_add(1);
            });
        });
    }

    group.finish();
}

fn bench_xdr_compound_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("compound_encode");

    group.bench_function("write_res_4k", |b| {
        let res = Compound4Res {
            status: NfsStat4::Ok,
            tag: String::new(),
            resarray: vec![
                NfsResop4::Sequence(
                    NfsStat4::Ok,
                    Some(SequenceRes4 {
                        sessionid: [0u8; 16],
                        sequenceid: 1,
                        slotid: 0,
                        highest_slotid: 63,
                        target_highest_slotid: 63,
                        status_flags: 0,
                    }),
                ),
                NfsResop4::Putfh(NfsStat4::Ok),
                NfsResop4::Write(
                    NfsStat4::Ok,
                    Some(WriteRes4 {
                        count: 4096,
                        committed: FILE_SYNC4,
                        writeverf: [0u8; 8],
                    }),
                ),
            ],
        };
        let mut buf = BytesMut::with_capacity(256);
        b.iter(|| {
            buf.clear();
            black_box(&res).encode(&mut buf);
        });
    });

    group.bench_function("read_res_64k", |b| {
        let data = vec![0xab_u8; 65536];
        let res = Compound4Res {
            status: NfsStat4::Ok,
            tag: String::new(),
            resarray: vec![
                NfsResop4::Sequence(
                    NfsStat4::Ok,
                    Some(SequenceRes4 {
                        sessionid: [0u8; 16],
                        sequenceid: 1,
                        slotid: 0,
                        highest_slotid: 63,
                        target_highest_slotid: 63,
                        status_flags: 0,
                    }),
                ),
                NfsResop4::Putfh(NfsStat4::Ok),
                NfsResop4::Read(
                    NfsStat4::Ok,
                    Some(ReadRes4 {
                        eof: false,
                        data,
                    }),
                ),
            ],
        };
        let mut buf = BytesMut::with_capacity(70000);
        b.iter(|| {
            buf.clear();
            black_box(&res).encode(&mut buf);
        });
    });

    group.bench_function("getattr_res", |b| {
        let res = Compound4Res {
            status: NfsStat4::Ok,
            tag: String::new(),
            resarray: vec![
                NfsResop4::Sequence(
                    NfsStat4::Ok,
                    Some(SequenceRes4 {
                        sessionid: [0u8; 16],
                        sequenceid: 1,
                        slotid: 0,
                        highest_slotid: 63,
                        target_highest_slotid: 63,
                        status_flags: 0,
                    }),
                ),
                NfsResop4::Putfh(NfsStat4::Ok),
                NfsResop4::Getattr(
                    NfsStat4::Ok,
                    Some(Fattr4 {
                        attrmask: {
                            let mut bm = Bitmap4::new();
                            bm.set(FATTR4_TYPE);
                            bm.set(FATTR4_CHANGE);
                            bm.set(FATTR4_SIZE);
                            bm.set(FATTR4_FILEID);
                            bm.set(FATTR4_MODE);
                            bm.set(FATTR4_NUMLINKS);
                            bm.set(FATTR4_TIME_MODIFY);
                            bm
                        },
                        attr_vals: vec![0u8; 64],
                    }),
                ),
                NfsResop4::Getfh(NfsStat4::Ok, Some(NfsFh4(vec![0, 0, 0, 0, 0, 0, 0, 1]))),
            ],
        };
        let mut buf = BytesMut::with_capacity(512);
        b.iter(|| {
            buf.clear();
            black_box(&res).encode(&mut buf);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_tcp_round_trip, bench_xdr_compound_encode);
criterion_main!(benches);
