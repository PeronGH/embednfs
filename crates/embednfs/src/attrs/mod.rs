//! NFSv4.1 attribute synthesis, encoding, and decoding helpers.

mod decode;
mod encode;
mod synthesize;

pub(crate) use decode::decode_setattr;
pub(crate) use encode::encode_fattr4;
pub(crate) use synthesize::synthesize_file_attr;

#[cfg(test)]
mod tests;
