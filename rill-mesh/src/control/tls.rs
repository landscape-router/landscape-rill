//! 控制面 TLS 传输（mTLS 侧由握手协议承担；此处仅服务端单向认证）

use crate::control::BoxResult;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub async fn client_tls_stream(
    host: &str,
    port: u16,
    ca_cert_pem: &[u8],
) -> BoxResult<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    let certs: Vec<_> = CertificateDer::pem_slice_iter(ca_cert_pem).collect::<Result<_, _>>()?;
    for cert in certs {
        roots.add(cert)?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    // tokio 的 (host, port) 走 getaddrinfo（容器内 compose DNS/公网 DNS 均可解析）
    let tcp = TcpStream::connect((host, port)).await?;
    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())?;
    Ok(connector.connect(server_name, tcp).await?)
}

pub async fn server_tls_stream(
    listener: &mut tokio::net::TcpListener,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> BoxResult<tokio_rustls::server::TlsStream<TcpStream>> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(cert_pem).collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::pem_slice_iter(key_pem)
        .next()
        .transpose()?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no key"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (tcp, _) = listener.accept().await?;
    Ok(acceptor.accept(tcp).await?)
}

/// 构建服务端 TLS acceptor（一次性建配置，多连接复用；REQ-051 状态端点用）
pub fn server_tls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> BoxResult<TlsAcceptor> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(cert_pem).collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::pem_slice_iter(key_pem)
        .next()
        .transpose()?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no key"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// 已接受 TCP 连接上的 TLS 握手（accept 由调用方完成——select 里只跑裸
/// accept 才取消安全，握手在 spawn 任务里进行不得被周期分支取消击杀）
pub async fn server_tls_accept(
    tcp: TcpStream,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> BoxResult<tokio_rustls::server::TlsStream<TcpStream>> {
    let acceptor = server_tls_acceptor(cert_pem, key_pem)?;
    Ok(acceptor.accept(tcp).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tls_echo_two_frames() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut params = rcgen::CertificateParams::new(vec!["coord.test".into()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let ca = params.self_signed(&key_pair).unwrap();
        let cert = ca.pem().into_bytes();
        let key = key_pair.serialize_pem().into_bytes();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cert2 = cert.clone();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let mut tls = server_tls_stream(&mut listener, &cert2, &key)
                .await
                .unwrap();
            let f1 = crate::framing::read_frame(&mut tls).await.unwrap();
            let _ = f1;
            let reply1 = b"response-one".to_vec();
            let reply2 = b"push-with-larger-body".to_vec();
            crate::framing::write_frame(&mut tls, &reply1)
                .await
                .unwrap();
            crate::framing::write_frame(&mut tls, &reply2)
                .await
                .unwrap();
        });
        let host = addr.ip().to_string();
        let mut tls = client_tls_stream(&host, addr.port(), &cert).await.unwrap();
        crate::framing::write_frame(&mut tls, b"hello".as_slice())
            .await
            .unwrap();
        let r1 = crate::framing::read_frame(&mut tls).await.unwrap();
        let r2 = crate::framing::read_frame(&mut tls).await.unwrap();
        drop(server);
        assert_eq!(r1, b"response-one");
        assert_eq!(r2, b"push-with-larger-body");
    }
}
