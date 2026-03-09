use bytes::{Bytes, BytesMut};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use embednfs_proto::xdr::*;
use embednfs_proto::*;

fn bench_xdr_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("xdr_primitives");

    group.bench_function("encode_u32", |b| {
        let mut buf = BytesMut::with_capacity(64);
        b.iter(|| {
            buf.clear();
            black_box(42u32).encode(&mut buf);
        });
    });

    group.bench_function("decode_u32", |b| {
        let mut template = BytesMut::with_capacity(4);
        42u32.encode(&mut template);
        let frozen = template.freeze();
        b.iter(|| {
            let mut src = frozen.clone();
            black_box(u32::decode(&mut src).unwrap());
        });
    });

    group.bench_function("encode_u64", |b| {
        let mut buf = BytesMut::with_capacity(64);
        b.iter(|| {
            buf.clear();
            black_box(0xdead_beef_cafe_babeu64).encode(&mut buf);
        });
    });

    group.bench_function("encode_opaque_8", |b| {
        let data = [0u8; 8];
        let mut buf = BytesMut::with_capacity(64);
        b.iter(|| {
            buf.clear();
            encode_opaque(&mut buf, black_box(&data));
        });
    });

    group.bench_function("encode_opaque_128", |b| {
        let data = [0xab_u8; 128];
        let mut buf = BytesMut::with_capacity(256);
        b.iter(|| {
            buf.clear();
            encode_opaque(&mut buf, black_box(&data));
        });
    });

    group.bench_function("decode_opaque_128", |b| {
        let mut template = BytesMut::with_capacity(256);
        encode_opaque(&mut template, &[0xab_u8; 128]);
        let frozen = template.freeze();
        b.iter(|| {
            let mut src = frozen.clone();
            black_box(decode_opaque(&mut src).unwrap());
        });
    });

    group.bench_function("encode_string_short", |b| {
        let s = String::from("hello");
        let mut buf = BytesMut::with_capacity(64);
        b.iter(|| {
            buf.clear();
            black_box(&s).encode(&mut buf);
        });
    });

    group.bench_function("encode_string_long", |b| {
        let s = "a".repeat(255);
        let mut buf = BytesMut::with_capacity(512);
        b.iter(|| {
            buf.clear();
            black_box(&s).encode(&mut buf);
        });
    });

    group.finish();
}

fn bench_bitmap4(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitmap4");

    group.bench_function("encode_2word", |b| {
        let mut bm = Bitmap4::new();
        bm.set(0);
        bm.set(4);
        bm.set(5);
        bm.set(33);
        bm.set(49);
        let mut buf = BytesMut::with_capacity(64);
        b.iter(|| {
            buf.clear();
            black_box(&bm).encode(&mut buf);
        });
    });

    group.bench_function("decode_2word", |b| {
        let mut bm = Bitmap4::new();
        bm.set(0);
        bm.set(4);
        bm.set(5);
        bm.set(33);
        bm.set(49);
        let mut template = BytesMut::with_capacity(64);
        bm.encode(&mut template);
        let frozen = template.freeze();
        b.iter(|| {
            let mut src = frozen.clone();
            black_box(Bitmap4::decode(&mut src).unwrap());
        });
    });

    group.bench_function("is_set", |b| {
        let mut bm = Bitmap4::new();
        bm.set(0);
        bm.set(4);
        bm.set(33);
        bm.set(49);
        b.iter(|| {
            black_box(bm.is_set(black_box(33)));
        });
    });

    group.finish();
}

fn bench_stateid(c: &mut Criterion) {
    let mut group = c.benchmark_group("stateid");

    group.bench_function("encode", |b| {
        let stateid = Stateid4 {
            seqid: 1,
            other: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };
        let mut buf = BytesMut::with_capacity(64);
        b.iter(|| {
            buf.clear();
            black_box(&stateid).encode(&mut buf);
        });
    });

    group.bench_function("decode", |b| {
        let stateid = Stateid4 {
            seqid: 1,
            other: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };
        let mut template = BytesMut::with_capacity(64);
        stateid.encode(&mut template);
        let frozen = template.freeze();
        b.iter(|| {
            let mut src = frozen.clone();
            black_box(Stateid4::decode(&mut src).unwrap());
        });
    });

    group.finish();
}

fn bench_compound_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("compound_response");

    group.bench_function("encode_sequence_getattr_getfh", |b| {
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
                            bm.set(0);
                            bm.set(1);
                            bm.set(4);
                            bm.set(5);
                            bm.set(33);
                            bm.set(49);
                            bm
                        },
                        attr_vals: vec![0u8; 128],
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

    group.bench_function("encode_read_1k", |b| {
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
                        data: vec![0xab; 1024],
                    }),
                ),
            ],
        };
        let mut buf = BytesMut::with_capacity(2048);
        b.iter(|| {
            buf.clear();
            black_box(&res).encode(&mut buf);
        });
    });

    group.bench_function("encode_read_64k", |b| {
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
                        data: vec![0xab; 65536],
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

    group.bench_function("decode_compound_sequence_putfh_getattr", |b| {
        // Build a COMPOUND request: SEQUENCE + PUTFH + GETATTR
        let mut raw = BytesMut::with_capacity(256);
        // tag (empty string)
        encode_opaque(&mut raw, &[]);
        // minorversion = 1
        1u32.encode(&mut raw);
        // op count = 3
        3u32.encode(&mut raw);
        // SEQUENCE
        OP_SEQUENCE.encode(&mut raw);
        raw.extend_from_slice(&[0u8; 16]); // sessionid (fixed opaque 16, no length prefix)
        1u32.encode(&mut raw); // sequenceid
        0u32.encode(&mut raw); // slotid
        63u32.encode(&mut raw); // highest_slotid
        0u32.encode(&mut raw); // cachethis = false
        // PUTFH
        OP_PUTFH.encode(&mut raw);
        encode_opaque(&mut raw, &[0, 0, 0, 0, 0, 0, 0, 1]);
        // GETATTR
        OP_GETATTR.encode(&mut raw);
        let mut bm = Bitmap4::new();
        bm.set(0);
        bm.set(1);
        bm.set(4);
        bm.set(5);
        bm.encode(&mut raw);

        let frozen = raw.freeze();
        b.iter(|| {
            let mut src = frozen.clone();
            black_box(Compound4Args::decode(&mut src).unwrap());
        });
    });

    group.finish();
}

fn bench_rpc_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("rpc_header");

    group.bench_function("decode_auth_sys", |b| {
        let mut raw = BytesMut::with_capacity(256);
        // xid
        1u32.encode(&mut raw);
        // msg type (call = 0)
        0u32.encode(&mut raw);
        // rpc version
        2u32.encode(&mut raw);
        // program
        100003u32.encode(&mut raw);
        // version
        4u32.encode(&mut raw);
        // procedure
        1u32.encode(&mut raw);
        // cred: flavor=AUTH_SYS(1), body
        1u32.encode(&mut raw);
        let mut auth_body = BytesMut::with_capacity(64);
        0u32.encode(&mut auth_body); // stamp
        encode_opaque(&mut auth_body, b"localhost"); // machinename
        501u32.encode(&mut auth_body); // uid
        20u32.encode(&mut auth_body); // gid
        0u32.encode(&mut auth_body); // gids count
        encode_opaque(&mut raw, &auth_body);
        // verf: AUTH_NONE
        0u32.encode(&mut raw);
        encode_opaque(&mut raw, &[]);

        let frozen = raw.freeze();
        b.iter(|| {
            let mut src = frozen.clone();
            black_box(RpcCallHeader::decode(&mut src).unwrap());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_xdr_primitives,
    bench_bitmap4,
    bench_stateid,
    bench_compound_response,
    bench_rpc_header,
);
criterion_main!(benches);
