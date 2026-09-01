use crate::BoxResult;
use futures_util::StreamExt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::AbstractDevice;
use tun::AsyncDevice;

#[cfg(target_os = "windows")]
pub const PACKET_INFORMATION_LENGTH: usize = 4;
#[cfg(not(target_os = "windows"))]
pub const PACKET_INFORMATION_LENGTH: usize = 0;

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub mtu: u16,
    pub address4: Option<(Ipv4Addr, u8)>,
    pub address6: Option<(Ipv6Addr, u8)>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "land0".into(),
            mtu: 1420,
            address4: None,
            address6: None,
        }
    }
}

pub struct TunDevice {
    device: AsyncDevice,
    mtu: u16,
}

impl TunDevice {
    pub async fn open(config: &TunConfig) -> BoxResult<Self> {
        let mut cfg = tun::configure();
        cfg.tun_name(&config.name).mtu(config.mtu).up();
        if let Some((addr, prefix)) = config.address4 {
            cfg.address(addr).netmask(prefix_netmask4(prefix));
        }
        let device = tun::create_as_async(&cfg)?;
        // tun crate 的地址配置走 SIOCSIFADDR ioctl，仅支持 IPv4；
        // IPv6 地址经 rtnetlink 自设（tailscale 同款做法）。
        if let Some((addr, prefix)) = config.address6 {
            set_ipv6_address(&device.tun_name()?, addr, prefix).await?;
        }
        Ok(Self {
            device,
            mtu: config.mtu,
        })
    }

    pub fn name(&self) -> String {
        self.device.tun_name().unwrap_or_else(|_| "tun".into())
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub async fn read_packet(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = vec![0u8; self.mtu as usize + PACKET_INFORMATION_LENGTH];
        let n = self.device.read(&mut buf).await?;
        buf.truncate(n);
        #[cfg(target_os = "windows")]
        if buf.len() < PACKET_INFORMATION_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "short tun read",
            ));
        }
        #[cfg(target_os = "windows")]
        buf.drain(..PACKET_INFORMATION_LENGTH);
        Ok(buf)
    }

    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<(), std::io::Error> {
        if packet.len() > self.mtu as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "packet exceeds tun mtu",
            ));
        }
        if PACKET_INFORMATION_LENGTH == 0 {
            self.device.write_all(packet).await
        } else {
            let mut buf = Vec::with_capacity(packet.len() + PACKET_INFORMATION_LENGTH);
            buf.extend_from_slice(&[0u8; PACKET_INFORMATION_LENGTH]);
            buf.extend_from_slice(packet);
            self.device.write_all(&buf).await
        }
    }
}

/// rtnetlink 为已创建接口添加 IPv6 地址（tun crate 的 ioctl 路径不支持 IPv6）
pub async fn set_ipv6_address(name: &str, addr: Ipv6Addr, prefix: u8) -> BoxResult<()> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links
        .next()
        .await
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "link not found"))??;
    let index = link.header.index;
    handle
        .address()
        .add(index, IpAddr::V6(addr), prefix)
        .execute()
        .await?;
    Ok(())
}

pub fn prefix_netmask4(prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(mask)
}

pub fn classify_local(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask4() {
        assert_eq!(prefix_netmask4(24), Ipv4Addr::from(u32::MAX << 8));
        assert_eq!(prefix_netmask4(0), Ipv4Addr::from(0));
        assert_eq!(prefix_netmask4(32), Ipv4Addr::from(u32::MAX));
    }

    #[test]
    fn classify() {
        assert!(classify_local(&"192.168.1.1".parse().unwrap()));
        assert!(classify_local(&"127.0.0.1".parse().unwrap()));
        assert!(classify_local(&"169.254.1.1".parse().unwrap()));
        assert!(!classify_local(&"8.8.8.8".parse().unwrap()));
        assert!(classify_local(&"fd12::1".parse().unwrap()));
        assert!(classify_local(&"fe80::1".parse().unwrap()));
        assert!(!classify_local(&"2001:db8::1".parse().unwrap()));
    }
}
