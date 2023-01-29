use crate::tracker::Response;
use byteorder::{BigEndian, ByteOrder};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

pub struct Handler {
    id: usize,
    sock: UdpSocket,
    buf: [u8; 1500],
}

const RETRACKER_PORT: u16 = 9697;

impl Handler {
    pub fn new(reg: &amy::Registrar) -> io::Result<Handler> {
        let sock = UdpSocket::bind(("0.0.0.0", RETRACKER_PORT))?;
        sock.set_nonblocking(true)?;
        let id = reg.register(&sock, amy::Event::Read)?;
        Ok(Handler {
            id,
            sock,
            buf: [0; 1500],
        })
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn readable(&mut self) -> Vec<Response> {
        let mut resps = Vec::new();

        while let Ok((len, _)) = self.sock.recv_from(&mut self.buf[..]) {
            let header1 = BigEndian::read_u32(&self.buf[0..4]);
            let header2 = BigEndian::read_u32(&self.buf[4..8]);

            if header1 > 0 && header2 == 0 {
                let mut i = 8;

                while i < len {
                    let tmp_buf = &self.buf[i..i + 28];
                    let mut hash = [0; 20];
                    hash.clone_from_slice(&tmp_buf[..20]);
                    let ip = std::net::Ipv4Addr::from(BigEndian::read_u32(&tmp_buf[20..24]));
                    let port = BigEndian::read_u16(&tmp_buf[24..26]);
                    let _flags = BigEndian::read_u16(&tmp_buf[26..28]);
                    trace!(
                        "Recv retracker data hash: {:x?} ip: {} port: {} flags: {}",
                        hash,
                        ip,
                        port,
                        _flags
                    );

                    resps.push(Response::RETRACKER {
                        hash,
                        peers: vec![SocketAddr::new(IpAddr::V4(ip), port)],
                    });
                    i += 28;
                }
            } else {
                debug!(
                    "Received invalid packet with headers {:x} {:x} from retracker!",
                    header1, header2
                );
            }
        }
        resps
    }
}
