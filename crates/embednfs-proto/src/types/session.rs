use bytes::{Bytes, BytesMut};

use crate::xdr::*;

use super::basic::*;

/// Channel attributes for CREATE_SESSION.
#[derive(Debug, Clone)]
pub struct ChannelAttrs4 {
    pub headerpadsize: Count4,
    pub maxrequestsize: Count4,
    pub maxresponsesize: Count4,
    pub maxresponsesize_cached: Count4,
    pub maxoperations: Count4,
    pub maxrequests: Count4,
    pub rdma_ird: Vec<u32>,
}

impl XdrEncode for ChannelAttrs4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.headerpadsize.encode(dst);
        self.maxrequestsize.encode(dst);
        self.maxresponsesize.encode(dst);
        self.maxresponsesize_cached.encode(dst);
        self.maxoperations.encode(dst);
        self.maxrequests.encode(dst);
        (self.rdma_ird.len() as u32).encode(dst);
        for v in &self.rdma_ird {
            v.encode(dst);
        }
    }
}

impl XdrDecode for ChannelAttrs4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        Ok(ChannelAttrs4 {
            headerpadsize: u32::decode(src)?,
            maxrequestsize: u32::decode(src)?,
            maxresponsesize: u32::decode(src)?,
            maxresponsesize_cached: u32::decode(src)?,
            maxoperations: u32::decode(src)?,
            maxrequests: u32::decode(src)?,
            rdma_ird: decode_list(src)?,
        })
    }
}

impl Default for ChannelAttrs4 {
    fn default() -> Self {
        ChannelAttrs4 {
            headerpadsize: 0,
            maxrequestsize: 1_049_620,
            maxresponsesize: 1_049_620,
            maxresponsesize_cached: 6144,
            maxoperations: 16,
            maxrequests: 64,
            rdma_ird: vec![],
        }
    }
}

/// Callback security parameters.
#[derive(Debug, Clone)]
pub struct CallbackSecParms4 {
    pub cb_secflavor: u32,
}

impl XdrDecode for CallbackSecParms4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let cb_secflavor = u32::decode(src)?;
        match cb_secflavor {
            0 => {}
            1 => {
                let _stamp = u32::decode(src)?;
                let _machine = String::decode(src)?;
                let _uid = u32::decode(src)?;
                let _gid = u32::decode(src)?;
                let _gids: Vec<u32> = decode_list(src)?;
            }
            _ => {}
        }
        Ok(CallbackSecParms4 { cb_secflavor })
    }
}

#[derive(Debug, Clone)]
pub struct ClientOwner4 {
    pub verifier: Verifier4,
    pub ownerid: Vec<u8>,
}

impl XdrDecode for ClientOwner4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let vdata = decode_fixed_opaque(src, 8)?;
        let mut verifier = [0u8; 8];
        verifier.copy_from_slice(&vdata);
        let ownerid = decode_opaque(src)?;
        Ok(ClientOwner4 { verifier, ownerid })
    }
}

#[derive(Debug)]
pub enum StateProtect4A {
    None,
    MachCred { ops: StateProt4MachOps },
    Ssv { ssv: SsvProtInfo4 },
}

#[derive(Debug)]
pub struct StateProt4MachOps {
    pub enforce: Bitmap4,
    pub allow: Bitmap4,
}

#[derive(Debug)]
pub struct SsvProtInfo4 {
    pub ops: StateProt4MachOps,
    pub hash_algs: Vec<u32>,
    pub encr_algs: Vec<u32>,
    pub window: u32,
    pub num_gss_handles: u32,
}

#[derive(Debug, Clone)]
pub struct NfsImplId4 {
    pub domain: String,
    pub name: String,
    pub date: NfsTime4,
}

impl XdrEncode for NfsImplId4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.domain.encode(dst);
        self.name.encode(dst);
        self.date.encode(dst);
    }
}

impl XdrDecode for NfsImplId4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        Ok(NfsImplId4 {
            domain: String::decode(src)?,
            name: String::decode(src)?,
            date: NfsTime4::decode(src)?,
        })
    }
}

#[derive(Debug)]
pub struct ExchangeIdArgs4 {
    pub clientowner: ClientOwner4,
    pub flags: u32,
    pub state_protect: StateProtect4A,
    pub client_impl_id: Vec<NfsImplId4>,
}

#[derive(Debug)]
pub struct CreateSessionArgs4 {
    pub clientid: Clientid4,
    pub sequence: Sequenceid4,
    pub flags: u32,
    pub fore_chan_attrs: ChannelAttrs4,
    pub back_chan_attrs: ChannelAttrs4,
    pub cb_program: u32,
    pub sec_parms: Vec<CallbackSecParms4>,
}

#[derive(Debug)]
pub struct DestroySessionArgs4 {
    pub sessionid: Sessionid4,
}

#[derive(Debug)]
pub struct SequenceArgs4 {
    pub sessionid: Sessionid4,
    pub sequenceid: Sequenceid4,
    pub slotid: Slotid4,
    pub highest_slotid: Slotid4,
    pub cachethis: bool,
}

#[derive(Debug)]
pub struct ReclaimCompleteArgs4 {
    pub one_fs: bool,
}

#[derive(Debug)]
pub struct DestroyClientidArgs4 {
    pub clientid: Clientid4,
}

#[derive(Debug)]
pub struct BindConnToSessionArgs4 {
    pub sessionid: Sessionid4,
    pub dir: u32,
    pub use_conn_in_rdma_mode: bool,
}

#[derive(Debug)]
pub struct FreeStateidArgs4 {
    pub stateid: Stateid4,
}

#[derive(Debug)]
pub struct TestStateidArgs4 {
    pub stateids: Vec<Stateid4>,
}

#[derive(Debug)]
pub struct DelegReturnArgs4 {
    pub stateid: Stateid4,
}

#[derive(Debug)]
pub enum StateProtect4R {
    None,
}

#[derive(Debug, Clone)]
pub struct ServerOwner4 {
    pub minor_id: u64,
    pub major_id: Vec<u8>,
}

impl XdrEncode for ServerOwner4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.minor_id.encode(dst);
        encode_opaque(dst, &self.major_id);
    }
}

#[derive(Debug)]
pub struct ExchangeIdRes4 {
    pub clientid: Clientid4,
    pub sequenceid: Sequenceid4,
    pub flags: u32,
    pub state_protect: StateProtect4R,
    pub server_owner: ServerOwner4,
    pub server_scope: Vec<u8>,
    pub server_impl_id: Vec<NfsImplId4>,
}

#[derive(Debug)]
pub struct CreateSessionRes4 {
    pub sessionid: Sessionid4,
    pub sequenceid: Sequenceid4,
    pub flags: u32,
    pub fore_chan_attrs: ChannelAttrs4,
    pub back_chan_attrs: ChannelAttrs4,
}

#[derive(Debug)]
pub struct SequenceRes4 {
    pub sessionid: Sessionid4,
    pub sequenceid: Sequenceid4,
    pub slotid: Slotid4,
    pub highest_slotid: Slotid4,
    pub target_highest_slotid: Slotid4,
    pub status_flags: u32,
}

#[derive(Debug)]
pub struct BindConnToSessionRes4 {
    pub sessionid: Sessionid4,
    pub dir: u32,
    pub use_conn_in_rdma_mode: bool,
}

#[derive(Debug)]
pub struct SecinfoEntry4 {
    pub flavor: u32,
}

impl XdrEncode for SecinfoEntry4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.flavor.encode(dst);
    }
}
