//! NFSv4.1 protocol types per RFC 8881.

mod basic;
mod constants;
mod operations;
mod session;

pub use basic::*;
pub use constants::*;
pub use operations::*;
pub use session::*;

mod codec;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nfsstat4_v41_status_codes_match_rfc8881() {
        assert_eq!(NfsStat4::SequencePos as u32, 10064);
        assert_eq!(NfsStat4::ReqTooBig as u32, 10065);
        assert_eq!(NfsStat4::RepTooBig as u32, 10066);
        assert_eq!(NfsStat4::RepTooBigToCache as u32, 10067);
        assert_eq!(NfsStat4::RetryUncachedRep as u32, 10068);
        assert_eq!(NfsStat4::UnsafeCompound as u32, 10069);
        assert_eq!(NfsStat4::TooManyOps as u32, 10070);
        assert_eq!(NfsStat4::OpNotInSession as u32, 10071);
        assert_eq!(NfsStat4::ClientidBusy as u32, 10074);
        assert_eq!(NfsStat4::SeqFalseRetry as u32, 10076);
        assert_eq!(NfsStat4::BadHighSlot as u32, 10077);
        assert_eq!(NfsStat4::NotOnlyOp as u32, 10081);
        assert_eq!(NfsStat4::WrongCred as u32, 10082);
        assert_eq!(NfsStat4::WrongType as u32, 10083);
        assert_eq!(NfsStat4::DelegRevoked as u32, 10087);
    }

    #[test]
    fn test_nfsstat4_from_u32_decodes_newer_v41_errors() {
        assert_eq!(NfsStat4::from_u32(10064), NfsStat4::SequencePos);
        assert_eq!(NfsStat4::from_u32(10068), NfsStat4::RetryUncachedRep);
        assert_eq!(NfsStat4::from_u32(10071), NfsStat4::OpNotInSession);
        assert_eq!(NfsStat4::from_u32(10074), NfsStat4::ClientidBusy);
        assert_eq!(NfsStat4::from_u32(10081), NfsStat4::NotOnlyOp);
        assert_eq!(NfsStat4::from_u32(10082), NfsStat4::WrongCred);
        assert_eq!(NfsStat4::from_u32(10083), NfsStat4::WrongType);
    }
}
