// this file mostly written by AI
use crate::array_array::ArrayArray;
use crate::rw::{Reader, WriteCursor, Writer};
use crate::serdes::{
    Deserializable, DeserializeError, Serializable, deserialize_arrayarray_len_prior_knowledge,
};
use anyhow::anyhow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const SOCKS_VERSION: u8 = 5;
const MAX_NUM_CLIENT_METHODS: usize = 256;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ClientMethodSelection {
    pub(crate) methods: ArrayArray<u8, MAX_NUM_CLIENT_METHODS>,
}

impl Serializable for ClientMethodSelection {
    fn serialize<S: Writer>(&self, serializer: &mut S) {
        SOCKS_VERSION.serialize(serializer);
        let nmethods = self.methods.len() as u8;
        nmethods.serialize(serializer);
        serializer.write_unchecked(&self.methods);
    }
}

impl Deserializable for ClientMethodSelection {
    fn deserialize(read_cursor: &mut impl Reader) -> Result<Self, DeserializeError> {
        let version: u8 = read_cursor.read()?;
        if version != SOCKS_VERSION {
            return Err(anyhow!("Unsupported SOCKS version: {version}").into());
        }
        let nmethods: u8 = read_cursor.read::<u8>()?;
        let methods = deserialize_arrayarray_len_prior_knowledge(read_cursor, nmethods.into())?;
        Ok(ClientMethodSelection { methods })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ServerMethodSelection {
    pub(crate) method: u8,
}

impl Serializable for ServerMethodSelection {
    fn serialize<S: Writer>(&self, serializer: &mut S) {
        SOCKS_VERSION.serialize(serializer);
        self.method.serialize(serializer);
    }
}

impl Deserializable for ServerMethodSelection {
    fn deserialize(read_cursor: &mut impl Reader) -> Result<Self, DeserializeError> {
        let version: u8 = read_cursor.read()?;
        if version != SOCKS_VERSION {
            return Err(anyhow!("Unsupported SOCKS version: {version}").into());
        }
        let method: u8 = read_cursor.read()?;
        Ok(ServerMethodSelection { method })
    }
}

pub(crate) const MAX_SOCKS_DOMAIN_LEN: usize = 256;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum SocksAddress {
    Ip(IpAddr),
    Domain(ArrayArray<u8, MAX_SOCKS_DOMAIN_LEN>),
}

impl Serializable for SocksAddress {
    fn serialize<S: Writer>(&self, serializer: &mut S) {
        match self {
            SocksAddress::Ip(IpAddr::V4(addr)) => {
                1u8.serialize(serializer);
                serializer.write_unchecked(&addr.octets());
            }
            SocksAddress::Domain(domain) => {
                3u8.serialize(serializer);
                let len = domain.len() as u8;
                len.serialize(serializer);
                serializer.write_unchecked(domain);
            }
            SocksAddress::Ip(IpAddr::V6(addr)) => {
                4u8.serialize(serializer);
                serializer.write_unchecked(&addr.octets());
            }
        }
    }
}

impl Deserializable for SocksAddress {
    fn deserialize(reader: &mut impl Reader) -> Result<Self, DeserializeError> {
        let atyp: u8 = reader.read()?;
        match atyp {
            1 => {
                let addr = reader
                    .read_exact_comptime::<4>()
                    .ok_or(DeserializeError::Truncated)?;
                Ok(SocksAddress::Ip(IpAddr::V4(Ipv4Addr::from(addr))))
            }
            3 => {
                let len = usize::from(reader.read::<u8>()?);
                if len > MAX_SOCKS_DOMAIN_LEN {
                    return Err(anyhow!(
                        "SOCKS domain length {} exceeds max allowed {}",
                        len,
                        MAX_SOCKS_DOMAIN_LEN
                    )
                    .into());
                }
                if reader.num_read_bytes_left() < len {
                    return Err(DeserializeError::Truncated);
                }
                let mut domain_writer = WriteCursor::new(ArrayArray::new_empty(len));
                reader.read_as_much_as_possible(&mut domain_writer);
                assert!(domain_writer.num_write_bytes_left() == 0);
                Ok(SocksAddress::Domain(domain_writer.into_inner()))
            }
            4 => {
                let addr = reader
                    .read_exact_comptime::<16>()
                    .ok_or(DeserializeError::Truncated)?;
                Ok(SocksAddress::Ip(IpAddr::V6(Ipv6Addr::from(addr))))
            }
            _ => Err(anyhow!("Unknown address type: {atyp}").into()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub(crate) enum SocksCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl Serializable for SocksCommand {
    fn serialize<S: Writer>(&self, serializer: &mut S) {
        (*self as u8).serialize(serializer);
    }
}

impl Deserializable for SocksCommand {
    fn deserialize(read_cursor: &mut impl Reader) -> Result<Self, DeserializeError> {
        let cmd_byte: u8 = read_cursor.read()?;
        match cmd_byte {
            0x01 => Ok(SocksCommand::Connect),
            0x02 => Ok(SocksCommand::Bind),
            0x03 => Ok(SocksCommand::UdpAssociate),
            _ => Err(anyhow!("Unknown SOCKS command: {cmd_byte}").into()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct SocksDestination {
    pub(crate) address: SocksAddress,
    pub(crate) port: u16,
}

impl Serializable for SocksDestination {
    fn serialize<S: Writer>(&self, serializer: &mut S) {
        self.address.serialize(serializer);
        self.port.serialize(serializer);
    }
}

impl Deserializable for SocksDestination {
    fn deserialize(read_cursor: &mut impl Reader) -> Result<Self, DeserializeError> {
        let address: SocksAddress = read_cursor.read()?;
        let port: u16 = read_cursor.read()?;
        Ok(SocksDestination { address, port })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct SocksRequest {
    pub(crate) command: SocksCommand,
    pub(crate) destination: SocksDestination,
}
impl Serializable for SocksRequest {
    fn serialize<S: Writer>(&self, serializer: &mut S) {
        SOCKS_VERSION.serialize(serializer);
        self.command.serialize(serializer);
        0u8.serialize(serializer); // RSV
        self.destination.serialize(serializer);
    }
}

impl Deserializable for SocksRequest {
    fn deserialize(read_cursor: &mut impl Reader) -> Result<Self, DeserializeError> {
        let version: u8 = read_cursor.read()?;
        if version != SOCKS_VERSION {
            return Err(anyhow!("Unsupported SOCKS version: {version}").into());
        }
        let command: SocksCommand = read_cursor.read()?;
        let rsv: u8 = read_cursor.read()?;
        if rsv != 0 {
            return Err(anyhow!("RSV byte must be 0, but was {rsv}").into());
        }
        let destination: SocksDestination = read_cursor.read()?;
        Ok(SocksRequest {
            command,
            destination,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub(crate) enum SocksReplyCode {
    Succeeded = 0x00,
    GeneralSocksServerFailure = 0x01,
    ConnectionNotAllowedByRuleset = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl Serializable for SocksReplyCode {
    fn serialize<S: Writer>(&self, serializer: &mut S) {
        (*self as u8).serialize(serializer);
    }
}

impl Deserializable for SocksReplyCode {
    fn deserialize(read_cursor: &mut impl Reader) -> Result<Self, DeserializeError> {
        let code_byte: u8 = read_cursor.read()?;
        match code_byte {
            0x00 => Ok(SocksReplyCode::Succeeded),
            0x01 => Ok(SocksReplyCode::GeneralSocksServerFailure),
            0x02 => Ok(SocksReplyCode::ConnectionNotAllowedByRuleset),
            0x03 => Ok(SocksReplyCode::NetworkUnreachable),
            0x04 => Ok(SocksReplyCode::HostUnreachable),
            0x05 => Ok(SocksReplyCode::ConnectionRefused),
            0x06 => Ok(SocksReplyCode::TtlExpired),
            0x07 => Ok(SocksReplyCode::CommandNotSupported),
            0x08 => Ok(SocksReplyCode::AddressTypeNotSupported),
            _ => Err(anyhow!("Unknown SOCKS reply code: {code_byte}").into()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct SocksReply {
    pub(crate) reply_code: SocksReplyCode,
    pub(crate) bind: SocksDestination,
}

impl Serializable for SocksReply {
    fn serialize<S: Writer>(&self, serializer: &mut S) {
        SOCKS_VERSION.serialize(serializer);
        self.reply_code.serialize(serializer);
        0u8.serialize(serializer); // RSV
        self.bind.serialize(serializer);
    }
}

impl Deserializable for SocksReply {
    fn deserialize(read_cursor: &mut impl Reader) -> Result<Self, DeserializeError> {
        let version: u8 = read_cursor.read()?;
        if version != SOCKS_VERSION {
            return Err(anyhow!("Unsupported SOCKS version: {version}").into());
        }
        let reply_code: SocksReplyCode = read_cursor.read()?;
        let rsv: u8 = read_cursor.read()?;
        if rsv != 0 {
            return Err(anyhow!("RSV byte must be 0, but was {rsv}").into());
        }
        let destination: SocksDestination = read_cursor.read()?;
        Ok(SocksReply {
            reply_code,
            bind: destination,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::array_array::ArrayArray;
    use crate::rw::{ReadCursor, WriteCursor};

    const ROUNDTRIP_BUFFER_LEN: usize = 1024;

    fn assert_roundtrip<T>(msg: &T)
    where
        T: Serializable + Deserializable + PartialEq + std::fmt::Debug,
    {
        let buf = ArrayArray::<u8, ROUNDTRIP_BUFFER_LEN>::new_empty(ROUNDTRIP_BUFFER_LEN);
        let mut write_cursor = WriteCursor::new(buf);
        msg.serialize(&mut write_cursor);
        let written_buf = write_cursor.into_inner();

        let mut read_cursor = ReadCursor::new(written_buf);
        let roundtripped_msg = T::deserialize(&mut read_cursor).unwrap();

        assert_eq!(msg, &roundtripped_msg);
    }

    #[test]
    fn roundtrip_client_method_selection() {
        let msg = ClientMethodSelection {
            methods: ArrayArray::new(&[0, 1, 2, 3]),
        };
        assert_roundtrip(&msg);
    }

    #[test]
    fn roundtrip_server_method_selection() {
        let msg = ServerMethodSelection { method: 1 };
        assert_roundtrip(&msg);
    }

    #[test]
    fn roundtrip_socks_request_v4() {
        let msg = SocksRequest {
            command: SocksCommand::Connect,
            destination: SocksDestination {
                address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                port: 8080,
            },
        };
        assert_roundtrip(&msg);
    }

    #[test]
    fn roundtrip_socks_request_domain() {
        let msg = SocksRequest {
            command: SocksCommand::Connect,
            destination: SocksDestination {
                address: SocksAddress::Domain(ArrayArray::new(b"example.com")),
                port: 8080,
            },
        };
        assert_roundtrip(&msg);
    }

    #[test]
    fn roundtrip_socks_request_v6() {
        let msg = SocksRequest {
            command: SocksCommand::Connect,
            destination: SocksDestination {
                address: SocksAddress::Ip(IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,
                ))),
                port: 8080,
            },
        };
        assert_roundtrip(&msg);
    }

    #[test]
    fn roundtrip_socks_reply_v4() {
        let msg = SocksReply {
            reply_code: SocksReplyCode::Succeeded,
            bind: SocksDestination {
                address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                port: 8080,
            },
        };
        assert_roundtrip(&msg);
    }

    #[test]
    fn roundtrip_socks_reply_domain() {
        let msg = SocksReply {
            reply_code: SocksReplyCode::Succeeded,
            bind: SocksDestination {
                address: SocksAddress::Domain(ArrayArray::new(b"example.com")),
                port: 8080,
            },
        };
        assert_roundtrip(&msg);
    }

    #[test]
    fn roundtrip_socks_reply_v6() {
        let msg = SocksReply {
            reply_code: SocksReplyCode::Succeeded,
            bind: SocksDestination {
                address: SocksAddress::Ip(IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,
                ))),
                port: 8080,
            },
        };
        assert_roundtrip(&msg);
    }
}
