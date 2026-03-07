use bytes::BytesMut;

use embednfs_proto::xdr::{XdrDecode, XdrEncode};
use embednfs_proto::*;

use crate::attrs::{decode_setattr, encode_fattr4};
use crate::fs::{FileAttr, FsInfo};

#[test]
fn test_decode_setattr_masks_file_type_bits_from_mode() {
    let mut bitmap = Bitmap4::new();
    bitmap.set(FATTR4_MODE);

    let mut vals = BytesMut::new();
    0o100644u32.encode(&mut vals);

    let attrs = decode_setattr(&Fattr4 {
        attrmask: bitmap,
        attr_vals: vals.to_vec(),
    })
    .unwrap();

    assert_eq!(attrs.mode, Some(0o644));
}

#[test]
fn test_encode_fattr4_masks_mode_to_permission_bits() {
    let mut request = Bitmap4::new();
    request.set(FATTR4_MODE);

    let attr = FileAttr {
        mode: 0o100644,
        ..FileAttr::default()
    };
    let fh = NfsFh4(vec![1, 2, 3, 4]);
    let fattr = encode_fattr4(&attr, &request, &fh, &FsInfo::default());
    let mut src = bytes::Bytes::from(fattr.attr_vals);

    assert_eq!(u32::decode(&mut src).unwrap(), 0o644);
}
