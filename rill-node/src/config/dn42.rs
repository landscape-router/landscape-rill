//! dn42 接入配置（DN42_LEG §5）：加载即校验（fail-closed，对齐 REQ-038 风格）。
//! WG 密钥为 wg genkey/pubkey 的 base64 格式——手搓解码，不引第三方 crate（对齐 rilld hex 先例）。

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use landscape_rill_core::route::Prefix;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dn42Config {
    pub local_as: u32,
    pub bgp_id: Ipv4Addr,
    /// 建议 hold time（秒，0 = 禁用）
    pub hold_time: u16,
    /// export stub：只公告的自家前缀
    pub own_prefixes: Vec<String>,
    pub peers: Vec<Dn42PeerConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dn42PeerConfig {
    /// 会话/路由标识（节点内唯一）
    pub name: String,
    /// 对端 underlay UDP 端点
    pub endpoint: SocketAddr,
    /// 对端 WG 公钥（base64，44 字符）
    pub public_key: String,
    /// 可选 PSK（base64，44 字符）
    pub preshared_key: Option<String>,
    /// 本端隧道地址（/30 + /126 内）
    pub local_v4: Ipv4Addr,
    pub local_v6: Ipv6Addr,
    /// 对端隧道地址（BGP 目标）
    pub peer_v4: Ipv4Addr,
    pub peer_v6: Ipv6Addr,
    pub peer_as: u32,
    pub bgp_port: u16,
    pub local_bgp_port: u16,
    /// import 白名单（covered-by 语义，DN42_LEG §4）
    pub whitelist: Vec<String>,
    /// 会话级前缀数上限（None = 不限）
    pub max_prefixes: Option<u32>,
}

/// base64（标准字母表，带 padding）→ 32 字节；WG 密钥格式
pub fn wg_key_decode(s: &str) -> Result<[u8; 32], String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let invalid = || format!("bad wg key: not base64 ({len} chars)", len = s.len());
    let body = s.strip_suffix('=').ok_or_else(invalid)?;
    if body.len() != 43 {
        return Err(invalid());
    }
    let mut out = [0u8; 32];
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut pos = 0;
    for ch in body.bytes() {
        let v = TABLE.iter().position(|&t| t == ch).ok_or_else(invalid)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[pos] = ((acc >> bits) & 0xff) as u8;
            pos += 1;
        }
    }
    Ok(out)
}

impl Dn42Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.local_as == 0 {
            return Err("dn42.local_as must be non-zero".into());
        }
        if self.bgp_id.is_unspecified() || self.bgp_id.is_broadcast() {
            return Err("dn42.bgp_id must be a valid router id".into());
        }
        for p in &self.own_prefixes {
            Prefix::parse(p).map_err(|_| format!("dn42.own_prefixes: bad cidr {p}"))?;
        }
        if self.peers.is_empty() {
            return Err("dn42.peers must not be empty".into());
        }
        let mut names = std::collections::HashSet::new();
        for peer in &self.peers {
            Self::validate_peer(peer)?;
            if !names.insert(peer.name.as_str()) {
                return Err(format!("dn42.peers: duplicate name {}", peer.name));
            }
        }
        Ok(())
    }

    fn validate_peer(peer: &Dn42PeerConfig) -> Result<(), String> {
        let bad = |what: &str| -> String { format!("dn42.peers[{}]: {what}", peer.name) };
        if peer.name.is_empty() {
            return Err("dn42.peers: empty name".into());
        }
        if peer.endpoint.port() == 0 {
            return Err(bad("endpoint port must be non-zero"));
        }
        wg_key_decode(&peer.public_key).map_err(|e| bad(&e))?;
        if let Some(psk) = &peer.preshared_key {
            wg_key_decode(psk).map_err(|e| bad(&e))?;
        }
        if peer.local_v4 == peer.peer_v4 || peer.local_v6 == peer.peer_v6 {
            return Err(bad("tunnel addresses must differ from peer's"));
        }
        if peer.peer_as == 0 {
            return Err(bad("peer_as must be non-zero"));
        }
        if peer.bgp_port == 0 || peer.local_bgp_port == 0 {
            return Err(bad("bgp ports must be non-zero"));
        }
        if peer.whitelist.is_empty() {
            // fail-closed：空白名单 = 拒绝一切，几乎必是配置错误
            return Err(bad("whitelist must not be empty"));
        }
        for w in &peer.whitelist {
            Prefix::parse(w).map_err(|_| bad(&format!("whitelist: bad cidr {w}")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_dn42() -> Dn42Config {
        Dn42Config {
            local_as: 4242420001,
            bgp_id: Ipv4Addr::new(172, 20, 100, 1),
            hold_time: 90,
            own_prefixes: vec!["172.20.1.0/24".into()],
            peers: vec![Dn42PeerConfig {
                name: "peer-r".into(),
                endpoint: "192.168.243.10:51820".parse().unwrap(),
                public_key: "AAAAAEFHi7EhP8z1TTT7mpY2SnnHbDFOxdTb+FSveCE=".into(),
                preshared_key: None,
                local_v4: Ipv4Addr::new(172, 20, 100, 1),
                local_v6: "fd00:100::1".parse().unwrap(),
                peer_v4: Ipv4Addr::new(172, 20, 100, 2),
                peer_v6: "fd00:100::2".parse().unwrap(),
                peer_as: 4242420002,
                bgp_port: 179,
                local_bgp_port: 10179,
                whitelist: vec!["172.20.0.0/14".into(), "fd00::/8".into()],
                max_prefixes: Some(1000),
            }],
        }
    }

    #[test]
    fn valid_dn42_passes() {
        assert_eq!(valid_dn42().validate(), Ok(()));
    }

    #[test]
    fn wg_key_decode_rejects_garbage() {
        // 32 字节全零的 base64（合法 WG 密钥格式）
        let zeros = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(wg_key_decode(zeros).unwrap(), [0u8; 32]);
        assert!(wg_key_decode("short").is_err());
        assert!(wg_key_decode("AAAA=").is_err());
        // 非 base64 字母表
        assert!(wg_key_decode("####*AAA*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_err());
        // 缺 padding
        assert!(wg_key_decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
    }

    #[test]
    fn dn42_config_fail_closed() {
        let mut c = valid_dn42();
        c.local_as = 0;
        assert!(c.validate().is_err());
        let mut c = valid_dn42();
        c.own_prefixes = vec!["bad".into()];
        assert!(c.validate().is_err());
        let mut c = valid_dn42();
        c.peers = vec![];
        assert!(c.validate().is_err());
    }

    #[test]
    fn dn42_peer_fail_closed() {
        let mut c = valid_dn42();
        c.peers[0].name = "".into();
        assert!(c.validate().is_err());
        let mut c = valid_dn42();
        c.peers[0].whitelist = vec![];
        assert!(
            c.validate().is_err(),
            "空白名单 = 拒绝一切，配置必须显式给出"
        );
        let mut c = valid_dn42();
        c.peers[0].public_key = "not-base64!!".into();
        assert!(c.validate().is_err());
        let mut c = valid_dn42();
        c.peers[0].local_v4 = c.peers[0].peer_v4;
        assert!(c.validate().is_err());
        let mut c = valid_dn42();
        let dup = c.peers[0].clone();
        c.peers.push(dup);
        assert!(c.validate().is_err(), "peer 名重复拒绝");
    }
}
