use bytes::BytesMut;

use embednfs_proto::xdr::XdrEncode;
use embednfs_proto::*;

use super::util::{
    readdir_dir_info_len, readdir_entry_len, readdir_entry_list_item_len, readdir_resok_len,
    xdr_opaque_len,
};

fn sample_entry(name: &str, fileid: u64) -> Entry4 {
    let mut bitmap = Bitmap4::new();
    bitmap.set(FATTR4_FILEID);
    bitmap.set(FATTR4_TYPE);

    let mut attr_vals = BytesMut::new();
    NfsFtype4::Reg.encode(&mut attr_vals);
    fileid.encode(&mut attr_vals);

    Entry4 {
        cookie: fileid,
        name: name.to_string(),
        attrs: Fattr4 {
            attrmask: bitmap,
            attr_vals: attr_vals.to_vec(),
        },
    }
}

#[test]
fn test_readdir_entry_len_matches_encoded_form() {
    let entry = sample_entry("hello.txt", 42);
    let mut encoded = BytesMut::new();
    entry.cookie.encode(&mut encoded);
    entry.name.encode(&mut encoded);
    entry.attrs.encode(&mut encoded);

    assert_eq!(readdir_entry_len(&entry), encoded.len());
    assert_eq!(readdir_entry_list_item_len(&entry), encoded.len() + 4);
    assert_eq!(readdir_dir_info_len(&entry), 8 + xdr_opaque_len(entry.name.len()));
}

#[test]
fn test_readdir_resok_len_matches_readop_encoding() {
    let entries = vec![sample_entry("a.txt", 1), sample_entry("b.txt", 2)];
    let result = ReaddirRes4 {
        cookieverf: [1, 2, 3, 4, 5, 6, 7, 8],
        entries,
        eof: true,
    };

    let mut encoded = BytesMut::new();
    NfsResop4::Readdir(NfsStat4::Ok, Some(result)).encode(&mut encoded);

    let expected_entries = vec![sample_entry("a.txt", 1), sample_entry("b.txt", 2)];
    assert_eq!(readdir_resok_len(&expected_entries, true), encoded.len() - 8);
}
