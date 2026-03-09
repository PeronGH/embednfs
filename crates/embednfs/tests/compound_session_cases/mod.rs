use bytes::BytesMut;
use embednfs_proto::xdr::*;
use embednfs_proto::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::*;

mod lifecycle;
mod misc;
mod protocol_sequence;
