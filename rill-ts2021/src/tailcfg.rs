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

/// "mkey:<hex64>" → 32B 公钥（tailscale key.MachinePublic 文本格式）
pub fn parse_machine_public(s: &str) -> Result<[u8; 32], String> {
    let hex_str = s
        .strip_prefix("mkey:")
        .ok_or_else(|| format!("bad machine key prefix: {s}"))?;
    if hex_str.len() != 64 {
        return Err(format!("bad machine key length: {}", hex_str.len()));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("bad machine key hex: {e}"))?;
    }
    Ok(out)
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
