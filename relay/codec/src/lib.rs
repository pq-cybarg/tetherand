//! Tetherand transport frame codec.
//!
//! Frames are length-prefixed:
//!   [len: u32 BE][ver: u8][ty: u8][resv: u16][payload...]
//!
//! `len` counts every byte after itself.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use byteorder::{BigEndian, ByteOrder};
use thiserror::Error;

pub const FRAME_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 4 + 1 + 1 + 2; // len + ver + ty + resv
pub const MAX_PAYLOAD: usize = u16::MAX as usize - 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    IpPacket = 1,
    Control = 2,
    Handshake = 3,
}

impl FrameType {
    pub fn from_u8(b: u8) -> Result<Self, CodecError> {
        match b {
            1 => Ok(FrameType::IpPacket),
            2 => Ok(FrameType::Control),
            3 => Ok(FrameType::Handshake),
            _ => Err(CodecError::UnknownType(b)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub version: u8,
    pub ty: FrameType,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(ty: FrameType, payload: impl Into<Bytes>) -> Self {
        Self { version: FRAME_VERSION, ty, payload: payload.into() }
    }

    pub fn encode(&self) -> Result<Bytes, CodecError> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(CodecError::PayloadTooLarge(self.payload.len()));
        }
        let body_len = 1 + 1 + 2 + self.payload.len();
        let mut out = BytesMut::with_capacity(4 + body_len);
        out.put_u32(body_len as u32);
        out.put_u8(self.version);
        out.put_u8(self.ty as u8);
        out.put_u16(0); // reserved
        out.put(self.payload.clone());
        Ok(out.freeze())
    }

    /// Try to decode one frame from `buf`. On success, the frame's bytes are
    /// consumed from `buf` and `Ok(Some(frame))` is returned. If not enough
    /// bytes are present yet, `Ok(None)` is returned and `buf` is left intact.
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>, CodecError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let body_len = BigEndian::read_u32(&buf[..4]) as usize;
        if body_len < 4 {
            return Err(CodecError::HeaderTooShort(body_len));
        }
        if body_len > 4 + MAX_PAYLOAD {
            return Err(CodecError::PayloadTooLarge(body_len - 4));
        }
        let total = 4 + body_len;
        if buf.len() < total {
            return Ok(None);
        }
        buf.advance(4);
        let version = buf.get_u8();
        let ty = FrameType::from_u8(buf.get_u8())?;
        let _resv = buf.get_u16();
        let payload_len = body_len - 4;
        let payload = buf.split_to(payload_len).freeze();
        Ok(Some(Self { version, ty, payload }))
    }
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("unknown frame type {0}")]
    UnknownType(u8),
    #[error("header body length {0} is shorter than required 4")]
    HeaderTooShort(usize),
    #[error("payload length {0} exceeds maximum (65531 bytes)")]
    PayloadTooLarge(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ip_packet() {
        let frame = Frame::new(FrameType::IpPacket, Bytes::from_static(&[1, 2, 3, 4, 5]));
        let bytes = frame.encode().unwrap();
        // header: len=9 (u32) + ver=1 + ty=1 + resv=0,0 + 5 payload bytes
        assert_eq!(bytes.len(), 4 + 9);
        let mut buf = BytesMut::from(&bytes[..]);
        let decoded = Frame::decode(&mut buf).unwrap().expect("frame");
        assert_eq!(decoded.version, FRAME_VERSION);
        assert_eq!(decoded.ty, FrameType::IpPacket);
        assert_eq!(&decoded.payload[..], &[1, 2, 3, 4, 5]);
        assert!(buf.is_empty(), "no trailing bytes");
    }

    #[test]
    fn partial_input_returns_none() {
        let frame = Frame::new(FrameType::Control, Bytes::from_static(&[0xAA; 12]));
        let bytes = frame.encode().unwrap();
        for cut in 0..bytes.len() {
            let mut buf = BytesMut::from(&bytes[..cut]);
            assert!(Frame::decode(&mut buf).unwrap().is_none(), "cut={cut}");
        }
        let mut buf = BytesMut::from(&bytes[..]);
        assert!(Frame::decode(&mut buf).unwrap().is_some());
    }

    #[test]
    fn decode_then_decode_two_frames() {
        let a = Frame::new(FrameType::IpPacket, Bytes::from_static(b"hello")).encode().unwrap();
        let b = Frame::new(FrameType::Handshake, Bytes::from_static(b"world!")).encode().unwrap();
        let mut buf = BytesMut::with_capacity(a.len() + b.len());
        buf.extend_from_slice(&a);
        buf.extend_from_slice(&b);
        let f1 = Frame::decode(&mut buf).unwrap().unwrap();
        let f2 = Frame::decode(&mut buf).unwrap().unwrap();
        assert_eq!(&f1.payload[..], b"hello");
        assert_eq!(&f2.payload[..], b"world!");
        assert!(buf.is_empty());
    }

    #[test]
    fn unknown_type_rejected() {
        let mut bad = BytesMut::new();
        bad.put_u32(4);    // body_len
        bad.put_u8(1);     // version
        bad.put_u8(99);    // unknown type
        bad.put_u16(0);
        let err = Frame::decode(&mut bad).unwrap_err();
        assert!(matches!(err, CodecError::UnknownType(99)));
    }

    #[test]
    fn payload_too_large_rejected_on_encode() {
        let big = Bytes::from(vec![0u8; MAX_PAYLOAD + 1]);
        let err = Frame::new(FrameType::IpPacket, big).encode().unwrap_err();
        assert!(matches!(err, CodecError::PayloadTooLarge(_)));
    }
}
