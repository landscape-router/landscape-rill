//! tailcfg 最小消息集（JSON over HTTP/2，TS2021_LEG §2 消息层）。
//! 字段名对齐 tailscale tailcfg v1.101.0-pre（headscale 0.29.3 锁定并以此解码）；
//! 只覆盖 /machine/register 往返所需子集，未知字段服务端忽略。

use serde::{Deserialize, Serialize};

/// tailcfg.CurrentCapabilityVersion @ tailscale v1.101.0-pre；headscale 0.29.3 最低接受 113。
/// 同时用作 controlbase prologue 版本与 RegisterRequest.Version（tailscale 客户端同源）。
pub const CURRENT_CAP_VERSION: u16 = 141;

/// 服务端在 msg2 后经 noise 流下发的引导信息（5B magic + 4B 长度 + JSON）
#[derive(Debug, Clone, Deserialize)]
pub struct EarlyNoise {
    #[serde(rename = "nodeKeyChallenge")]
    pub node_key_challenge: String,
}

/// /machine/register 响应（JSON 字段名 = Go 结构体字段名）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    #[serde(rename = "User")]
    pub user: serde_json::Value,
    #[serde(rename = "Login")]
    pub login: serde_json::Value,
    #[serde(rename = "NodeKeyExpired")]
    pub node_key_expired: bool,
    #[serde(rename = "MachineAuthorized")]
    pub machine_authorized: bool,
    #[serde(rename = "AuthURL")]
    pub auth_url: String,
    #[serde(rename = "Error")]
    pub error: String,
}

impl RegisterResponse {
    /// 注册成功判定：无错误且无需跳转授权页
    pub fn is_success(&self) -> bool {
        self.error.is_empty() && self.auth_url.is_empty()
    }
}

/// /key 端点响应（OverTLSPublicKeyResponse）：客户端经 TLS 预取服务端 Noise 公钥。
/// 官方 control server 用 Go 默认字段名 "PublicKey"，headscale 用小写 "publicKey"（实测）——alias 兼容两者
#[derive(Debug, Clone, Deserialize)]
pub struct OverTLSPublicKeyResponse {
    #[serde(rename = "publicKey", alias = "PublicKey")]
    pub public_key: String,
}

/// "<prefix>:<hex64>" → 32B 公钥（tailscale key.MarshalText 同格式）
fn parse_key_hex(prefix: &str, s: &str) -> Result<[u8; 32], String> {
    let hex_str = s
        .strip_prefix(prefix)
        .ok_or_else(|| format!("bad key prefix (want {prefix}): {s}"))?;
    if hex_str.len() != 64 {
        return Err(format!("bad key length: {}", hex_str.len()));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("bad key hex: {e}"))?;
    }
    Ok(out)
}

/// "mkey:<hex64>" → 32B 公钥（tailscale key.MachinePublic 文本格式）
pub fn parse_machine_public(s: &str) -> Result<[u8; 32], String> {
    parse_key_hex("mkey:", s)
}

/// "nodekey:<hex64>" → 32B 公钥（tailcfg Node.Key）
pub fn parse_node_public(s: &str) -> Result<[u8; 32], String> {
    parse_key_hex("nodekey:", s)
}

/// RegisterRequest JSON（NodeKey = "nodekey:<hex>"，tailscale key.MarshalText 同格式；
/// Expiry/Followup 等缺省由服务端按零值处理）
pub fn register_request_json(node_key: &[u8; 32], auth_key: &str, hostname: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "Version": CURRENT_CAP_VERSION,
        "NodeKey": format!("nodekey:{}", hex(node_key)),
        "Auth": { "AuthKey": auth_key },
        "Hostinfo": { "Hostname": hostname },
    });
    serde_json::to_vec(&body).expect("serialize RegisterRequest")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// MapRequest JSON：Stream=true 长轮询（headscale 0.29 对 Stream=false+OmitPeers=false
/// 不回 body，完整 netmap 仅经长轮询首个 MapResponse 下发——poll.go serve/serveLongPoll 对照）
pub fn map_request_json(
    node_key: &[u8; 32],
    disco_key: &[u8; 32],
    hostname: &str,
    endpoints: &[String],
    stream: bool,
    preferred_derp: Option<u16>,
) -> Vec<u8> {
    let hostinfo = match preferred_derp {
        Some(rid) => serde_json::json!({"Hostname": hostname, "NetInfo": {"PreferredDERP": rid}}),
        None => serde_json::json!({"Hostname": hostname}),
    };
    let body = serde_json::json!({
        "Version": CURRENT_CAP_VERSION,
        "NodeKey": format!("nodekey:{}", hex(node_key)),
        // DiscoKey 必须携带：tailscaled 引擎(nmcfg)跳过无 DiscoKey 且无 Home DERP 的
        // peer("doesn't offer DERP or disco")——缺失则本节点不会进入对端 WG 设备。
        // v1 不实现 disco 协议，仅声明密钥占位（TS2021_LEG §2.2）。
        "DiscoKey": format!("discokey:{}", hex(disco_key)),
        "Hostinfo": hostinfo,
        // 上报本端 UDP 端点（对端回包/主动发起的依据）；Stream=true 时服务端忽略，
        // 端点经 Lite 更新（Stream=false + OmitPeers=true）单独上报。
        "Endpoints": endpoints,
        "Stream": stream,
        "OmitPeers": false,
        "KeepAlive": true,
    });
    serde_json::to_vec(&body).expect("serialize MapRequest")
}

/// Lite 端点更新（Stream=false + OmitPeers=true）：服务端只存端点并回 200 空 body
pub fn map_endpoints_update_json(
    node_key: &[u8; 32],
    disco_key: &[u8; 32],
    hostname: &str,
    endpoints: &[String],
    preferred_derp: Option<u16>,
) -> Vec<u8> {
    let hostinfo = match preferred_derp {
        Some(rid) => serde_json::json!({"Hostname": hostname, "NetInfo": {"PreferredDERP": rid}}),
        None => serde_json::json!({"Hostname": hostname}),
    };
    let body = serde_json::json!({
        "Version": CURRENT_CAP_VERSION,
        "NodeKey": format!("nodekey:{}", hex(node_key)),
        "DiscoKey": format!("discokey:{}", hex(disco_key)),
        "Hostinfo": hostinfo,
        "Endpoints": endpoints,
        "Stream": false,
        "OmitPeers": true,
    });
    serde_json::to_vec(&body).expect("serialize MapRequest")
}

/// /machine/map 长轮询响应（只取本里程碑所需字段；未知字段忽略）
#[derive(Debug, Clone, Deserialize)]
pub struct MapResponse {
    #[serde(rename = "Node")]
    pub node: Option<NetNode>,
    #[serde(rename = "Peers", default)]
    pub peers: Vec<NetPeer>,
    #[serde(rename = "DERPMap", default)]
    pub derp_map: Option<serde_json::Value>,
}

/// netmap DERPMap 中选定的 DERP 节点（region id + 接入地址；
/// 服务端 derp 公钥经问候帧下发，无需从 DERPMap 取）
#[derive(Debug, Clone)]
pub struct DerpNode {
    pub region_id: u16,
    pub hostname: String,
    pub port: u16,
}

impl MapResponse {
    /// 取 DERPMap 中首个可用节点（e2e 场景 = headscale 内嵌 DERP 单 region）
    pub fn derp_node(&self) -> Option<DerpNode> {
        let regions = self.derp_map.as_ref()?.get("Regions")?.as_object()?;
        let (_, region) = regions.iter().next()?;
        let region_id = region.get("RegionID")?.as_u64()? as u16;
        let node = region.get("Nodes")?.as_array()?.first()?;
        Some(DerpNode {
            region_id,
            hostname: node.get("HostName")?.as_str()?.to_owned(),
            port: node.get("DERPPort")?.as_u64()? as u16,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetNode {
    #[serde(rename = "Addresses", default)]
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetPeer {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Vec<String>,
    #[serde(rename = "AllowedIPs", default)]
    pub allowed_ips: Vec<String>,
}

impl NetPeer {
    /// 对端 node key（WG 静态公钥）
    pub fn node_key(&self) -> Result<[u8; 32], String> {
        parse_node_public(&self.key)
    }

    /// AllowedIPs 中的首个 IPv4（无 CIDR 掩码剥离）
    pub fn first_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        self.allowed_ips.iter().find_map(|a| {
            let ip = a.split('/').next()?;
            ip.parse().ok()
        })
    }
}

impl MapResponse {
    /// 本节点首个 IPv4 地址（如 100.64.0.1）
    pub fn self_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        self.node.as_ref()?.addresses.iter().find_map(|a| {
            let ip = a.split('/').next()?;
            ip.parse().ok()
        })
    }
}
