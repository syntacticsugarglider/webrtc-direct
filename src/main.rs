#[macro_use]
extern crate trackable;

use async_std::net::UdpSocket;
use bytecodec::{DecodeExt, EncodeExt};
use errno::{errno, Errno};
use failure::Fail;
use futures::{
    channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender},
    executor::{block_on, ThreadPool},
    future::pending,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    lock::Mutex,
    task::{Context, Poll},
    Future, Sink, SinkExt, Stream, StreamExt, TryStreamExt,
};
use lazy_static::lazy_static;
use num_enum::{TryFromPrimitive};
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod},
    x509::X509,
};
use openssl_async::SslAcceptorExt;
use sctp::{
    in_addr, linger, sctp_assoc_value, sctp_event, sctp_rcvinfo, sctp_sendv_spa, sctp_sockstore,
    sockaddr, sockaddr_conn, sockaddr_in, socket, usrsctp_accept, usrsctp_bind, usrsctp_conninput,
    usrsctp_init, usrsctp_listen, usrsctp_register_address, usrsctp_sendv,
    usrsctp_set_non_blocking, usrsctp_setsockopt, usrsctp_socket,
    usrsctp_sysctl_get_sctp_sendspace, AF_CONN, AF_INET, AF_INET6, E2BIG, EACCES, EADDRINUSE,
    EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN, EALREADY, EAUTH, EBADARCH, ECONNREFUSED, ENETDOWN, ENOENT,
    EPERM, EQFULL, ESHUTDOWN, ETIMEDOUT, IPPROTO_SCTP, SCTP_ALL_ASSOC, SCTP_ASSOC_CHANGE,
    SCTP_ENABLE_STREAM_RESET, SCTP_EVENT, SCTP_NODELAY, SCTP_PEER_ADDR_CHANGE,
    SCTP_SENDER_DRY_EVENT, SCTP_SENDV_SPA, SCTP_SEND_FAILED_EVENT, SCTP_SEND_SNDINFO_VALID,
    SCTP_STREAM_RESET_EVENT, SOCK_STREAM, SOL_SOCKET, SO_LINGER, variadic_debug, usrsctp_sysctl_set_sctp_blackhole
};
use std::{
    collections::HashMap,
    convert::TryInto,
    ffi::{c_void, CString},
    fmt::{Debug, Display, self, Formatter},
    mem::{size_of, MaybeUninit},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::TryFromIntError,
    ops::DerefMut,
    os::raw::{c_char, c_int},
    pin::Pin,
    ptr,
    sync::Arc,
};
use stun_codec::{
    define_attribute_enums,
    rfc5245::attributes::IceControlled,
    rfc5389::{
        attributes::{Fingerprint, MessageIntegrity, XorMappedAddress},
        methods::BINDING,
    },
    Message, MessageClass, MessageDecoder, MessageEncoder, Method, TransactionId,
};
use zerocopy::AsBytes;

#[derive(AsBytes)]
#[repr(u8)]
enum DataMessageType {
    None = 0,
    Control = 50,
    Binary = 52,
    BinaryLast = 53,
    TextPartial = 54,
    TextLast = 51,
}

impl DataMessageType {
    fn as_u32(self) -> u32 {
        self.as_bytes()[0] as u32
    }
}

#[derive(AsBytes)]
#[repr(u8)]
enum ChannelType {
    Reliable = 0x00,
    ReliableUnordered = 0x80,
    PartialReliableRetransmit = 0x01,
    PartialReliableRetransmitUnordered = 0x81,
    PartialReliableTimed = 0x02,
    PartialReliableTimedUnordered = 0x82,
}

#[derive(AsBytes)]
#[repr(u8)]
enum MessageType {
    DataChannelOpen = 0x03,
}

#[derive(AsBytes)]
#[repr(u16)]
enum Priority {
    BelowNormal = 128,
    Normal = 256,
    High = 512,
    ExtraHigh = 1024,
}

#[derive(AsBytes)]
#[repr(C)]
struct DataChannelOpenHeader {
    message_type: MessageType,
    channel_type: ChannelType,
    priority: Priority,
    reliability: u32,
    label_length: u16,
    protocol_length: u16,
}

impl DataChannelOpenHeader {
    fn new_reliable(label: &str) -> Result<Vec<u8>, TryFromIntError> {
        let label = label.as_bytes();
        let mut data = DataChannelOpenHeader {
            message_type: MessageType::DataChannelOpen,
            channel_type: ChannelType::Reliable,
            priority: Priority::Normal,
            reliability: 0,
            label_length: label.len().try_into()?,
            protocol_length: 0,
        }
        .as_bytes()
        .to_vec();
        data.extend_from_slice(label);
        Ok(data)
    }
}

define_attribute_enums!(
    Attribute,
    AttributeDecoder,
    AttributeEncoder,
    [
        IceControlled,
        XorMappedAddress,
        MessageIntegrity,
        Fingerprint
    ]
);

lazy_static! {
    static ref POOL: ThreadPool = ThreadPool::new().unwrap();
}

unsafe extern "C" fn receive(
    sock: *mut socket,
    addr: sctp_sockstore,
    data: *mut c_void,
    len: usize,
    info: sctp_rcvinfo,
    flags: c_int,
    ulp_info: *mut c_void,
) -> c_int {
    println!("sctp receive");
    1
}

unsafe extern "C" fn send(_: *mut socket, _: u32) -> c_int {
    println!("send");
    0
}

unsafe extern "C" fn handle_send(
    addr: *mut c_void,
    buffer: *mut c_void,
    length: usize,
    _: u8,
    _: u8,
) -> c_int {
    println!("sctp send {} bytes", length);
    let sender = Box::from_raw(addr as *mut UnboundedSender<Vec<u8>>);
    let data = std::slice::from_raw_parts(buffer as *mut u8, length);
    sender.clone().start_send(data.to_vec()).unwrap();
    Box::leak(sender);
    0
}

pub struct ReadWrite<T: DerefMut + Unpin, U: DerefMut + Unpin>(Pin<T>, Pin<U>)
where
    T::Target: Sink<Vec<u8>, Error = futures::io::Error>,
    U::Target: AsyncRead;

impl<T: DerefMut + Unpin, U: DerefMut + Unpin> AsyncWrite for ReadWrite<T, U>
where
    T::Target: Sink<Vec<u8>, Error = futures::io::Error>,
    U::Target: AsyncRead,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, futures::io::Error>> {
        let ready = self.0.as_mut().poll_ready(cx)?;
        if let Poll::Pending = ready {
            return Poll::Pending;
        }
        Poll::Ready(self.0.as_mut().start_send(buf.to_vec()).map(|_| buf.len()))
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), futures::io::Error>> {
        self.0.as_mut().poll_flush(cx)
    }
    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), futures::io::Error>> {
        self.0.as_mut().poll_close(cx)
    }
}

impl<T: DerefMut + Unpin, U: DerefMut + Unpin> AsyncRead for ReadWrite<T, U>
where
    T::Target: Sink<Vec<u8>, Error = futures::io::Error>,
    U::Target: AsyncRead,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, futures::io::Error>> {
        self.1.as_mut().poll_read(cx, buf)
    }
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "sctp initialization failed: {}", _0)]
    Initialize(SCTPError),
    #[fail(display = "could not create socket: {}", _0)]
    Create(SCTPError),
    #[fail(display = "failed to set non-blocking mode: {}", _0)]
    SetNonBlocking(SCTPError),
    #[fail(display = "failed to set linger mode: {}", _0)]
    SetLinger(SCTPError),
    #[fail(display = "failed to set stream reset mode: {}", _0)]
    SetReset(SCTPError),
    #[fail(display = "failed to set nodelay: {}", _0)]
    SetNodelay(SCTPError),
    #[fail(display = "failed to set event: {}", _0)]
    SetEvent(SCTPError),
    #[fail(display = "failed to bind listener: {}", _0)]
    Bind(SCTPError),
    #[fail(display = "sctp listener failed: {}", _0)]
    Listen(SCTPError),
    #[fail(display = "{}", _0)]
    Other(#[fail(cause)] failure::Error),
    #[fail(display = "{}", _0)]
    IO(#[fail(cause)] async_std::io::Error),
    #[fail(display = "openssl error: {}", _0)]
    SSL(#[fail(cause)] openssl::error::ErrorStack),
    #[fail(display = "sctp accept failed {}", _0)]
    Accept(SCTPError),
    #[fail(display = "set blackhole failed {}", _0)]
    SetBlackhole(SCTPError),
}

impl From<async_std::io::Error> for Error {
    fn from(input: async_std::io::Error) -> Self {
        Error::IO(input)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(input: openssl::error::ErrorStack) -> Self {
        Error::SSL(input)
    }
}

#[derive(TryFromPrimitive, Debug)]
#[repr(u32)]
pub enum SCTPError {
    AddressInUse = EADDRINUSE,
    QueueFull = EQFULL,
    NoEntity = ENOENT,
    NetworkDown = ENETDOWN,
    AddressFamilyNotSupported = EAFNOSUPPORT,
    InsufficientPermissions = EPERM,
    ConnectionRefused = ECONNREFUSED,
    Shutdown = ESHUTDOWN,
    TimedOut = ETIMEDOUT,
    Unavailable = EAGAIN,
    None = 0,
}

impl Display for SCTPError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", match self {
            SCTPError::AddressInUse => "address in use",
            SCTPError::QueueFull => "queue full",
            SCTPError::NoEntity => "no such file or directory",
            SCTPError::NetworkDown => "network down",
            SCTPError::AddressFamilyNotSupported => "address family is not supported",
            SCTPError::InsufficientPermissions => "operation not permitted",
            SCTPError::ConnectionRefused => "connection refused",
            SCTPError::Shutdown => "connection is shut down",
            SCTPError::TimedOut => "connection timed out",
            SCTPError::Unavailable => "resource temporarily unavailable",
            SCTPError::None => "unknown or empty error"
        })
    }
}

fn get_error() -> Option<SCTPError> {
    let error = unsafe { *sctp::__error() } as u32;
    if error == 0 {
        return None;
    }
    error.try_into().ok()
}

fn check_error(err: fn(SCTPError) -> Error) -> Result<(), Error> {
    get_error().map(|e| Err(err(e))).unwrap_or(Ok(()))
}

fn error<T>(err: fn(SCTPError) -> Error) -> Result<T, Error> {
    if let Err(e) = check_error(err) {
        Err(e)
    } else {
        Err(err(SCTPError::None))
    }
}

#[derive(Fail, Debug)]
#[fail(display = "inet_pton failed: {}", _0)]
struct PtonError {
    cause: Errno,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
unsafe fn inet_pton(addr: IpAddr, dst: &mut in_addr) -> Result<(), PtonError> {
    extern "C" {
        fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
    }
    let address_string = CString::new(addr.to_string()).unwrap();
    if inet_pton(
        match addr {
            IpAddr::V4(_) => AF_INET as i32,
            IpAddr::V6(_) => {
                panic!("v6 address will overflow buffer");
            }
        },
        address_string.as_ptr(),
        &mut dst.s_addr as *mut u32 as *mut c_void,
    ) < 0
    {
        Err(PtonError { cause: errno() })
    } else {
        Ok(())
    }
}

struct Connection {
    receiver: UnboundedSender<Result<Vec<u8>, async_std::io::Error>>,
}

fn listen(
    sctp_addr: SocketAddr,
    udp_addr: SocketAddr,
    public_key: impl AsRef<[u8]>,
    private_key: impl AsRef<[u8]>,
) -> impl Future<Output = Result<(), Error>> {
    async move {
        let mut context = SslAcceptor::mozilla_intermediate(SslMethod::dtls())?;
        context.set_certificate(&*X509::from_pem(public_key.as_ref())?)?;
        context.set_private_key(&*PKey::private_key_from_pem(private_key.as_ref())?)?;
        context.check_private_key()?;
        let context = context.build();
        let socket = unsafe {
            usrsctp_init(0, Some(handle_send), Some(variadic_debug));
            check_error(Error::Initialize)?;
            if usrsctp_sysctl_set_sctp_blackhole(2) < 0 {
                return error(Error::SetBlackhole);
            }
            usrsctp_socket(
                AF_CONN as i32,
                SOCK_STREAM as i32,
                IPPROTO_SCTP as i32,
                Some(receive),
                Some(send),
                usrsctp_sysctl_get_sctp_sendspace() / 2,
                Box::into_raw(Box::new("test")) as *mut c_void,
            )
        };
        if socket.is_null() {
            return error(Error::Create);
        }
        if unsafe { usrsctp_set_non_blocking(socket, 1) < 0 } {
            return error(Error::SetNonBlocking);
        }
        let linger = linger {
            l_onoff: 1,
            l_linger: 0,
        };
        if unsafe {
            usrsctp_setsockopt(
                socket,
                SOL_SOCKET as i32,
                SO_LINGER as i32,
                &linger as *const linger as *const c_void,
                size_of::<linger>() as u32,
            )
        } < 0
        {
            return error(Error::SetLinger);
        }
        let reset = sctp_assoc_value {
            assoc_value: 1,
            assoc_id: SCTP_ALL_ASSOC,
        };
        if unsafe {
            usrsctp_setsockopt(
                socket,
                IPPROTO_SCTP as i32,
                SCTP_ENABLE_STREAM_RESET as i32,
                &reset as *const sctp_assoc_value as *const c_void,
                size_of::<sctp_assoc_value>() as u32,
            )
        } < 0
        {
            return error(Error::SetReset);
        }
        if unsafe {
            usrsctp_setsockopt(
                socket,
                IPPROTO_SCTP as i32,
                SCTP_NODELAY as i32,
                &1u32 as *const u32 as *const c_void,
                size_of::<u32>() as u32,
            )
        } < 0
        {
            return error(Error::SetNodelay);
        }
        let event_types = [
            SCTP_ASSOC_CHANGE,
            SCTP_PEER_ADDR_CHANGE,
            SCTP_SEND_FAILED_EVENT,
            SCTP_SENDER_DRY_EVENT,
            SCTP_STREAM_RESET_EVENT,
        ];
        for ty in event_types.iter() {
            let event = sctp_event {
                se_on: 1,
                se_assoc_id: SCTP_ALL_ASSOC,
                se_type: *ty as u16,
            };
            if unsafe {
                usrsctp_setsockopt(
                    socket,
                    IPPROTO_SCTP as i32,
                    SCTP_EVENT as i32,
                    &event as *const sctp_event as *const c_void,
                    size_of::<sctp_event>() as u32,
                )
            } < 0
            {
                return error(Error::SetEvent);
            }
        }
        let mut sockaddr: sockaddr_in = unsafe { MaybeUninit::zeroed().assume_init() };
        sockaddr.sin_family = AF_INET as u8;
        sockaddr.sin_port = sctp_addr.port();
        unsafe {
            inet_pton(sctp_addr.ip(), &mut sockaddr.sin_addr)
                .map_err(|e| Error::Other(e.into()))?
        };
        if unsafe {
            usrsctp_bind(
                socket,
                &mut sockaddr as *mut sockaddr_in as *mut sockaddr,
                size_of::<sockaddr_in>() as u32,
            )
        } < 0
        {
            return error(Error::Bind);
        }
        if unsafe { usrsctp_listen(socket, 1) } < 0 {
            return error(Error::Listen);
        }
        let udp = Arc::new(UdpSocket::bind(udp_addr).await?);
        let mut connections: HashMap<SocketAddr, Connection> = HashMap::new();
        let socket = socket as usize;
        POOL.spawn_ok(async move {
            loop {
                let mut buf = vec![0u8; 4096];
                let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
                let mut decoder = MessageDecoder::<Attribute>::new();
                if let Ok(Ok(stun)) = decoder.decode_from_bytes(&buf[0..len]) {
                    if stun.method() != BINDING {
                        continue;
                    }
                    let mut response = Message::<Attribute>::new(
                        MessageClass::SuccessResponse,
                        BINDING,
                        stun.transaction_id(),
                    );
                    response.add_attribute(
                        XorMappedAddress::new(SocketAddr::new(
                            if let IpAddr::V4(addr) = peer.ip() {
                                IpAddr::from((u32::from_le_bytes(addr.octets())).to_be_bytes())
                            } else {
                                panic!("not ipv4")
                            },
                            u16::from_le_bytes(peer.port().to_be_bytes()),
                        ))
                        .into(),
                    );
                    response.add_attribute(IceControlled::new(0).into());
                    response.add_attribute(
                        MessageIntegrity::new_short_term_credential(
                            &response,
                            "3S0OeHDz16aoWRK4tnALIsebH4nk9olF",
                        )
                        .unwrap()
                        .into(),
                    );
                    response.add_attribute(Fingerprint::new(&response).unwrap().into());
                    let mut encoder = MessageEncoder::new();
                    let bytes = encoder.encode_into_bytes(response.clone()).unwrap();
                    udp.send_to(bytes.as_ref(), peer).await.unwrap();
                    continue;
                }
                let connection = connections.get_mut(&peer);
                if let Some(connection) = connection {
                    connection.receiver.send(Ok(buf.clone())).await.unwrap();
                } else if len == 0 {
                    continue;
                } else {
                    let (mut in_sender, in_receiver) = unbounded();
                    connections.insert(
                        peer,
                        Connection {
                            receiver: in_sender.clone(),
                        },
                    );
                    let (out_sender, mut out_receiver): (_, UnboundedReceiver<Vec<u8>>) =
                        unbounded();
                    let u_socket = udp.clone();
                    POOL.spawn_ok(async move {
                        in_sender.send(Ok(buf.clone())).await.unwrap();
                        while let Some(item) = out_receiver.next().await {
                            u_socket.send_to(item.as_ref(), peer).await.unwrap();
                        }
                    });
                    let ssl = context.accept_async(ReadWrite(
                        Box::pin(out_sender.sink_map_err(|_| panic!())),
                        Box::pin(in_receiver.into_async_read()),
                    ));
                    let (sctp_sender, mut sctp_receiver): (_, UnboundedReceiver<Vec<u8>>) =
                        unbounded();
                    let sctp_sender = Box::into_raw(Box::new(sctp_sender)) as usize;
                    unsafe { usrsctp_register_address(sctp_sender as *mut c_void) };
                    POOL.spawn_ok(async move {
                        let ssl = Arc::new(Mutex::new(ssl.await.unwrap_or_else(|_| panic!())));
                        let read_ssl = ssl.clone();
                        POOL.spawn_ok(async move {
                            while let Some(item) = sctp_receiver.next().await {
                                ssl.lock().await.write(item.as_ref()).await.unwrap();
                            }
                        });
                        let mut addr: sockaddr_conn =
                            unsafe { MaybeUninit::zeroed().assume_init() };
                        /*let connection = unsafe {
                            usrsctp_accept(
                                socket as *mut socket,
                                &mut addr as *mut _ as *mut sockaddr,
                                &mut 4u32 as *mut u32,
                            )
                        };
                        if connection.is_null() {
                            check_error(Error::Accept).unwrap();
                        }
                        let mut send_info: sctp_sendv_spa =
                            unsafe { MaybeUninit::zeroed().assume_init() };
                        send_info.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
                        send_info.sendv_sndinfo.snd_ppid = DataMessageType::Control.as_u32();
                        send_info.sendv_sndinfo.snd_sid = 1;
                        println!("createdc");
                        let data = DataChannelOpenHeader::new_reliable("0").unwrap();
                        unsafe {
                            usrsctp_sendv(
                                connection,
                                data.as_ptr() as *const c_void,
                                data.len(),
                                ptr::null::<sockaddr>() as *mut sockaddr,
                                0,
                                &mut send_info as *mut _ as *mut c_void,
                                size_of::<sctp_sendv_spa>() as u32,
                                SCTP_SENDV_SPA,
                                0,
                            );
                        };*/
                        POOL.spawn_ok(async move {
                            let mut buf = vec![0u8; 4096];
                            loop {
                                let len = read_ssl.lock().await.read(&mut buf).await.unwrap();
                                unsafe {
                                    usrsctp_conninput(
                                        sctp_sender as *mut c_void,
                                        buf.as_ptr() as *const c_void,
                                        len,
                                        0,
                                    );
                                };
                            }
                        });
                    });
                    continue;
                }
            }
        });
        Ok(())
    }
}

static TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIJAJBEgIHU0mN4MA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0xNzA2MjAxODIzNDFaFw0yNzA2MTgxODIzNDFaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAN3KKAOFyeAiEkhmAOF5BAZOVln6RvZ9Rw6x0Sez/hNWssFFCQCvRu0eDEPt
e0u1+eHEFP64RbS9+yqso+BcXJ7umq94UpOpE81DsNh8lc+/zLPJf2lJwiL6uYmT
YkRgqjm5/kNsqvWACpEOfQ8mZIy/oWftqHsSBuavF4IQbFh/WfNfOpgdl5KY3cO4
BmM55rsEzu3/Y15Z8i/63v0JnL0cD+aBmR4Lf20XMPU+Dnh5mS9x6FxFiYORi5Bs
XMRse3gvT+fhgMXMQJYuAde6Sm2JxHUFBHAkz9e4RGf+CYlueIvrT5FWgUw6DF9j
Sk/Nv+O6eZqrCIu0Jg1omppuc80CAwEAAaNQME4wHQYDVR0OBBYEFAEMKQzFh9GY
5Tn5AehzZvk4SjOsMB8GA1UdIwQYMBaAFAEMKQzFh9GY5Tn5AehzZvk4SjOsMAwG
A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAGK+PHJ4DU7R3277cJiCDk0Q
5fTCGy6J8ZJTLDhdpYtUSlvBTJdBfqGXvew1k+/vvU+o5mduKINVHCr/SIeimIAu
orV0/ZD6Athv3/oBhs1EYuQ39FAY6CqrGsIeW15GY4dPX6zwGzibO8Fsad0aGyjG
xqMlhqcI10XWlIEhDniY5DmXuOWVN35acXvZxT3B44EU7lukDpD6mMzG4zQYznlP
aDrOJ6ONoArHcikzGgSC9ve4VFqG7dNwLBFTPiv0kjBA179GhJL+M0vx2ItDOc3I
xPl1a9GNc5eXehdf0gm4YObA2Yi3G7FhWF7OFLg97q+ENGSpVeYXQ9Xi+fwq3so=
-----END CERTIFICATE-----"#;

static TEST_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA3cooA4XJ4CISSGYA4XkEBk5WWfpG9n1HDrHRJ7P+E1aywUUJ
AK9G7R4MQ+17S7X54cQU/rhFtL37Kqyj4Fxcnu6ar3hSk6kTzUOw2HyVz7/Ms8l/
aUnCIvq5iZNiRGCqObn+Q2yq9YAKkQ59DyZkjL+hZ+2oexIG5q8XghBsWH9Z8186
mB2Xkpjdw7gGYznmuwTO7f9jXlnyL/re/QmcvRwP5oGZHgt/bRcw9T4OeHmZL3Ho
XEWJg5GLkGxcxGx7eC9P5+GAxcxAli4B17pKbYnEdQUEcCTP17hEZ/4JiW54i+tP
kVaBTDoMX2NKT82/47p5mqsIi7QmDWiamm5zzQIDAQABAoIBAQDIsi4TQfWzxCEX
MnaJkaB6tFifg0LDugma2n2Rl+bKSSHokjfbTsC3wQEIVtXDZSCBk5YMCWPKcj/e
FesVE38csn13W0IeLFmm3SIiRFqsa7so1aVd+UibrpZGUAAUMATZx9y11pe9H+hv
6tRv6SYD10SPbxeOhnmINdjn8USZrrSsgqskFZ+ZZw3p4bBnDZTmCu2iUV2BDCzB
JMrd09UPn9LYe0oVWmD/+19l8Dtd8yNjVTQTkK+NBoIgig3aWQV+yd71ezD8inHO
mef9HP09d3WA0i9dnbPTs5h0F9FC7izRUat6Zq3gIunlQFy1JuvPESIWh1v9TGBw
LtpsH65hAoGBAPRnt275RbmcT+jSfiYIL/Tl81omxKw3U8Y7egHXRLCmZIbor5bl
+TmoFBgoTYYm+M3DFK4iKJEaE4jiMmYt/AAlkkLLD/nWyExqWsguK+HJtjO8i7t4
feiN8flC5mg72JRB1MG0CmwiTmUm0GTOajGq08GsNA/rx0BJwbdsoEufAoGBAOhP
xsYZti45HSu1hMVHHxjOMlnjYPrUGdS75UVtvlkqnzZrZ5BkdnZq7cHxKtHz2oIL
mPlD702VJsgLy5mIxNBzHNYjKdZCXZOTRdCdRnbkUMXDdPes5g9Ok8l4qcoBt4dl
NCnfA7ufVRxtrWAlaMzxzyB3l7um9/4gIwaQN8kTAoGBAKS9kHB2B6CgE2D9GVjr
Zd/ubAUVYrYuqQJSrt+0ybFExzgEee793usVN049RFwrwsN3PmZN0ghUilxXE9+6
GUXEDX2GQKOIOgUAH2cVcDDGdVEUQx+/jScHHtaEWKhjxo3Qfed/QxM2YJ9f9VIt
rHkEC65dM86Tf//+d1v7FWVDAoGBAJ2WqGdvv6bBdalV3DgbE9w22+8gEIR2ZwNp
ZpDfbjV8dT5sQ3euvrF7vcdHOt3rhrma9m15CRde60zeu4FuRtyEifY1Kkc/A819
JOnsFoXGQYi2G117+yA9FIGiCcOPwJjnLSiOMTEQV6MOP4MuPVZxXilPFy3jiOzp
jfkA0ebjAoGAEFdZ2UoUS0GTqDheoQoY6YgbBmHVuUe7p1lnByX8S76iRQg1I3aS
4s94jgn2HPlYVpjhAVdHNg7aTK1O4x9vzu6Pnaqz2QagwdWuh0rKC6dI/RfyZC7x
fbjlY2dIKPvOQgyuYmrJLoco+M2VLSU8BRdlsIUu1Y+eConKkQrkLA4=
-----END RSA PRIVATE KEY-----"#;

fn main() {
    block_on(async move {
        listen(
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 5000),
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 61200),
            TEST_CERT,
            TEST_KEY,
        )
        .await
        .unwrap_or_else(|e| panic!(format!("{}", e)));
        pending::<()>().await;
    })
}
