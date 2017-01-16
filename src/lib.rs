//! SOCKS proxy support for Hyper clients
#![doc(html_root_url="https://docs.rs/hyper-socks/0.3.0")]
#![warn(missing_docs)]

extern crate socks;
extern crate hyper;

#[cfg(test)]
extern crate hyper_openssl;

use hyper::net::{NetworkConnector, HttpStream, HttpsStream, SslClient};
use socks::{Socks4Stream, Socks5Stream};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

/// A connector that will produce HttpStreams proxied over a SOCKS4 server.
#[derive(Debug)]
pub struct Socks4HttpConnector {
    addrs: Vec<SocketAddr>,
    userid: String,
}

impl Socks4HttpConnector {
    /// Creates a new `Socks4HttpConnector` which will connect to the specified
    /// proxy with the specified userid.
    pub fn new<T: ToSocketAddrs>(proxy: T, userid: &str) -> io::Result<Socks4HttpConnector> {
        Ok(Socks4HttpConnector {
            addrs: try!(proxy.to_socket_addrs()).collect(),
            userid: userid.to_owned(),
        })
    }
}

impl NetworkConnector for Socks4HttpConnector {
    type Stream = HttpStream;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> hyper::Result<HttpStream> {
        if scheme != "http" {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid scheme for HTTP")
                           .into());
        }

        let socket = try!(Socks4Stream::connect(&self.addrs[..], (host, port), &self.userid));
        Ok(HttpStream(socket.into_inner()))
    }
}

/// A connector that will produce HttpsStreams proxied over a SOCKS4 server.
#[derive(Debug)]
pub struct Socks4HttpsConnector<S> {
    addrs: Vec<SocketAddr>,
    userid: String,
    ssl: S,
}

impl<S: SslClient> Socks4HttpsConnector<S> {
    /// Creates a new `Socks4HttpsConnector` which will connect to the specified
    /// proxy with the specified userid, and use the provided SSL implementation
    /// to encrypt the resulting stream.
    pub fn new<T: ToSocketAddrs>(proxy: T, userid: &str, ssl: S) -> io::Result<Self> {
        Ok(Socks4HttpsConnector {
            addrs: try!(proxy.to_socket_addrs()).collect(),
            userid: userid.to_owned(),
            ssl: ssl,
        })
    }
}

impl<S: SslClient> NetworkConnector for Socks4HttpsConnector<S> {
    type Stream = HttpsStream<S::Stream>;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> hyper::Result<Self::Stream> {
        if scheme != "http" && scheme != "https" {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid scheme for HTTPS")
                           .into());
        }

        let socket = try!(Socks4Stream::connect(&self.addrs[..], (host, port), &self.userid));
        let stream = HttpStream(socket.into_inner());

        if scheme == "http" {
            Ok(HttpsStream::Http(stream))
        } else {
            Ok(HttpsStream::Https(try!(self.ssl.wrap_client(stream, host))))
        }
    }
}

/// A connector that will produce HttpStreams proxied over a SOCKS5 server.
#[derive(Debug)]
pub struct Socks5HttpConnector {
    addrs: Vec<SocketAddr>,
}

impl Socks5HttpConnector {
    /// Creates a new `Socks5HttpConnector` which will connect to the specified
    /// proxy.
    pub fn new<T: ToSocketAddrs>(proxy: T) -> io::Result<Socks5HttpConnector> {
        Ok(Socks5HttpConnector {
            addrs: try!(proxy.to_socket_addrs()).collect(),
        })
    }
}

impl NetworkConnector for Socks5HttpConnector {
    type Stream = HttpStream;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> hyper::Result<HttpStream> {
        if scheme != "http" {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid scheme for HTTP")
                           .into());
        }

        let socket = try!(Socks5Stream::connect(&self.addrs[..], (host, port)));
        Ok(HttpStream(socket.into_inner()))
    }
}

/// A connector that will produce HttpsStreams proxied over a SOCKS5 server.
#[derive(Debug)]
pub struct Socks5HttpsConnector<S> {
    addrs: Vec<SocketAddr>,
    ssl: S,
}

impl<S: SslClient> Socks5HttpsConnector<S> {
    /// Creates a new `Socks5HttpsConnector` which will connect to the specified proxy, and use the
    /// provided SSL implementation to encrypt the resulting stream.
    pub fn new<T: ToSocketAddrs>(proxy: T, ssl: S) -> io::Result<Self> {
        Ok(Socks5HttpsConnector {
            addrs: try!(proxy.to_socket_addrs()).collect(),
            ssl: ssl,
        })
    }
}

impl<S: SslClient> NetworkConnector for Socks5HttpsConnector<S> {
    type Stream = HttpsStream<S::Stream>;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> hyper::Result<Self::Stream> {
        if scheme != "http" && scheme != "https" {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid scheme for HTTPS")
                           .into());
        }

        let socket = try!(Socks5Stream::connect(&self.addrs[..], (host, port)));
        let stream = HttpStream(socket.into_inner());

        if scheme == "http" {
            Ok(HttpsStream::Http(stream))
        } else {
            Ok(HttpsStream::Https(try!(self.ssl.wrap_client(stream, host))))
        }
    }
}

#[cfg(test)]
mod test {
    use hyper;
    use hyper_openssl::OpensslClient;
    use std::io::Read;

    use super::*;

    #[test]
    fn google() {
        let connector = Socks4HttpConnector::new("127.0.0.1:8080", "").unwrap();
        let client = hyper::Client::with_connector(connector);
        let mut response = client.get("http://www.google.com").send().unwrap();

        assert!(response.status.is_success());
        let mut body = vec![];
        response.read_to_end(&mut body).unwrap();
    }

    #[test]
    fn google_ssl_http() {
        let ssl = OpensslClient::new().unwrap();
        let connector = Socks4HttpsConnector::new("127.0.0.1:8080", "", ssl).unwrap();
        let client = hyper::Client::with_connector(connector);
        let mut response = client.get("http://www.google.com").send().unwrap();

        assert!(response.status.is_success());
        let mut body = vec![];
        response.read_to_end(&mut body).unwrap();
    }

    #[test]
    fn google_ssl_https() {
        let ssl = OpensslClient::new().unwrap();
        let connector = Socks4HttpsConnector::new("127.0.0.1:8080", "", ssl).unwrap();
        let client = hyper::Client::with_connector(connector);
        let mut response = client.get("https://www.google.com").send().unwrap();

        assert!(response.status.is_success());
        let mut body = vec![];
        response.read_to_end(&mut body).unwrap();
    }

    #[test]
    fn google_v5() {
        let connector = Socks5HttpConnector::new("127.0.0.1:8080").unwrap();
        let client = hyper::Client::with_connector(connector);
        let mut response = client.get("http://www.google.com").send().unwrap();

        assert!(response.status.is_success());
        let mut body = vec![];
        response.read_to_end(&mut body).unwrap();
    }

    #[test]
    fn google_ssl_http_v5() {
        let ssl = OpensslClient::new().unwrap();
        let connector = Socks5HttpsConnector::new("127.0.0.1:8080", ssl).unwrap();
        let client = hyper::Client::with_connector(connector);
        let mut response = client.get("http://www.google.com").send().unwrap();

        assert!(response.status.is_success());
        let mut body = vec![];
        response.read_to_end(&mut body).unwrap();
    }

    #[test]
    fn google_ssl_https_v5() {
        let ssl = OpensslClient::new().unwrap();
        let connector = Socks5HttpsConnector::new("127.0.0.1:8080", ssl).unwrap();
        let client = hyper::Client::with_connector(connector);
        let mut response = client.get("https://www.google.com").send().unwrap();

        assert!(response.status.is_success());
        let mut body = vec![];
        response.read_to_end(&mut body).unwrap();
    }
}
