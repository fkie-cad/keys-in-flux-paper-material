// based on: https://github.com/rustls/rustls/blob/main/examples/src/bin/simpleclient.rs
use std::sync::Arc;
use std::net::TcpStream;
use std::io::{Read, Write, ErrorKind};
use rustls::{ClientConfig, ClientConnection, Stream, Error, DigitallySignedStruct, SignatureScheme,  
    client::danger::{
                    ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid
    }
};
use rustls::pki_types::{ServerName, CertificateDer, UnixTime};
use std::env;

// Custom verifier to accept any server certificate
#[derive(Debug)] struct MyVerifier;

impl ServerCertVerifier for MyVerifier {
    fn verify_server_cert(&self, _end_entity: &CertificateDer, _intermediates: &[CertificateDer], _server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: UnixTime) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error>{
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error>{
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Some of the supported signature schemes (should be enough for this application's purpose)
        vec![
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP521_SHA512,
        SignatureScheme::ED25519,
        SignatureScheme::ED448]
    }
}


fn main() {
    // Parse command-line arguments.
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <ip> <port>", args[0]);
        return;
    }
    let hostname = &args[1];
    let port = &args[2];
    let addr_with_port = format!("{}:{}", hostname, port);
    // Buffer for receiving data
    let mut buf = [0u8; 1024];

    // Using the "dangerous" API to set a custom certificate verifier
    // Restrict the protocol versions to TLS 1.2
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(MyVerifier))
        .with_no_client_auth();

    // Try to parse as IP address first, otherwise treat as DNS name
    let server_name = if let Ok(parsed_ip) = hostname.parse::<std::net::IpAddr>() {
        ServerName::IpAddress(parsed_ip.into())
    } else {
        ServerName::try_from(hostname.to_string())
            .expect("Invalid hostname")
    };
    
    // Establish a TCP connection to the server
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(&addr_with_port).unwrap();
    println!("TCP connected");

    // Ensure socket is in blocking mode for handshake
    sock.set_nonblocking(false).unwrap();

    {
        let mut tls = Stream::new(&mut conn, &mut sock);
        // send some data to trigger the TLS handshake
        tls.write_all(b"test").unwrap();
    } // tls is dropped here

    println!("Established TLS 1.2 connection.");
    println!("Waiting for server messages...");
    
    // Now recreate tls for the message loop
    let mut tls = Stream::new(&mut conn, &mut sock);
    
    loop {
        match tls.read(&mut buf) {
            Ok(0) => {
                println!("Received close_notify (clean shutdown by peer).");
                break;
            }
            Ok(n) => {
                let received = String::from_utf8_lossy(&buf[..n]);
                println!("Received application data: {}", received);
            }
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    // Non-blocking socket has no data, just wait a bit
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                } else {
                    // Check if error is related to a protocol issue
                    let error_str = format!("{:?}", e);
                    if error_str.contains("internal error") || 
                       error_str.contains("fatal alert") {
                        println!("Protocol error: {:?}", e);
                        println!("Received internal error fatal alert");
                    } else {
                        println!("Read error: {:?}", e);
                    }
                    break;
                }
            }
        }
    }

    println!("Disconnecting from server...");

    // Drop tls before accessing sock directly
    drop(tls);

    // shutdown the TCP connection so the peer sees EOF
    if let Err(e) = sock.shutdown(std::net::Shutdown::Both) {
        eprintln!("tcp shutdown error: {:?}", e);
    }

    // drop remaining resources explicitly
    drop(conn);
    drop(sock);

    println!("Disconnected. Process will remain active for 2 seconds before exiting.");
    std::thread::sleep(std::time::Duration::from_secs(2));
    println!("Client process exiting.");
}