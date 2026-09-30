//! ts2021 服务端 netmap 组帧（REQ-068，TS2021_LEG §4）：MapResponse JSON 构造，
//! 字段集对齐 headscale 0.29.3 实测帧（Node/Peers/DERPMap/DNSConfig/Domain/
//! PacketFilters/UserProfiles/ControlTime；线格式 = 4B LE 长度前缀 + JSON）。
//! 增量帧：PeersChanged（全条目 upsert）+ PeersRemoved（数字 node ID）。

use super::registry::NodeEntry;
use serde_json::{json, Value};

/// 组帧上下文（服务端配置派生，帧间不变）
#[derive(Debug, Clone)]
pub struct NetmapCtx {
    /// UserProfiles LoginName / Name 后缀用户段（v1 单用户）
    pub user: String,
    /// DNSConfig.Domains / Name 后缀域段
    pub dns_domain: String,
    /// Domain 字段（服务端主机名，仅展示语义）
    pub domain: String,
    pub derp_region: u16,
    pub derp_hostname: String,
    pub derp_port: u16,
}

/// RFC3339（UTC，秒精度；unix 秒 → 日期用 Howard Hinnant civil_from_days）
pub fn rfc3339(unix: u64) -> String {
    let days = (unix / 86400) as i64;
    let secs = unix % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// 节点 JSON（自身 Node 与 Peers 条目同构；headscale 实测字段集）
pub fn node_json(e: &NodeEntry, ctx: &NetmapCtx) -> Value {
    let addresses = e.addresses();
    // AllowedIPs = tailnet 地址 + 已批准广播路由（exit = 显式白名单放行的默认路由）
    let mut allowed = addresses.clone();
    allowed.extend(e.approved_routes.iter().cloned());
    json!({
        "ID": e.nid,
        "StableID": e.nid.to_string(),
        "Name": format!("{}.{}.{}.", e.hostname, ctx.user, ctx.dns_domain),
        "User": 1,
        "Key": format!("nodekey:{}", hex(&e.node_key)),
        "Machine": format!("mkey:{}", hex(&e.machine)),
        "DiscoKey": format!("discokey:{}", hex(&e.disco_key)),
        "Addresses": addresses,
        "AllowedIPs": allowed,
        "Endpoints": e.endpoints,
        "HomeDERP": e.preferred_derp.unwrap_or(ctx.derp_region),
        "Hostinfo": {
            "Hostname": e.hostname,
            "RoutableIPs": e.announced_routes,
        },
        "Created": rfc3339(e.created),
        "LastSeen": rfc3339(e.last_seen),
        "Cap": 141,
        "Online": e.online,
        "MachineAuthorized": true,
        "PrimaryRoutes": e.approved_routes,
        "CapMap": {
            "default-auto-update": [false],
            "https://tailscale.com/cap/file-sharing": [],
            "https://tailscale.com/cap/is-admin": [],
            "https://tailscale.com/cap/ssh": []
        }
    })
}

/// 帧封装：4B LE 长度 + JSON（headscale reservedResponseHeaderSize 语义）；
/// compress=true 时 JSON 体替换为 zstd 帧（官方客户端 MapRequest.Compress="zstd"
/// 后对每帧做 DecodeAll——严格解码无明文透传，e2e 实证）
fn frame(body: &Value, compress: bool) -> Vec<u8> {
    let json = serde_json::to_vec(body).expect("netmap json serializes");
    let payload = if compress {
        zstd_raw_frame(&json)
    } else {
        json
    };
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    out
}

/// 单帧 zstd 封装（RFC 8878）：magic 0xFD2FB528 + Frame_Header（单段、
/// 4B 内容长）+ 单个 Raw block（不压缩——v1 帧小，换来零 C 依赖，REQ-044
/// 哲学同源自研 base64）。任何 zstd 解码器（klauspost DecodeAll）可解
fn zstd_raw_frame(data: &[u8]) -> Vec<u8> {
    // 单帧可含多个 ≤128KB 块；map 帧远小于此，断言防御而非分块
    assert!(
        data.len() < 1 << 17,
        "netmap frame exceeds zstd raw block limit"
    );
    let mut out = Vec::with_capacity(data.len() + 12);
    out.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]); // magic（LE）
    out.push(0xA0); // FHD：FCS_field_size=4B（code 2）+ Single_Segment
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    // Block_Header 3B LE：size<<3 | type(Raw=0)<<1 | last=1
    let bh = ((data.len() as u32) << 3) | 1;
    out.extend_from_slice(&bh.to_le_bytes()[..3]);
    out.extend_from_slice(data);
    out
}

/// 全量 netmap 帧（Node 自身 + Peers 其余节点 + DERPMap + 静态段）
pub fn full_frame(
    self_entry: &NodeEntry,
    peers: &[NodeEntry],
    ctx: &NetmapCtx,
    now: u64,
    compress: bool,
) -> Vec<u8> {
    frame(
        &json!({
            "Node": node_json(self_entry, ctx),
            "Peers": peers.iter().map(|p| node_json(p, ctx)).collect::<Vec<_>>(),
            "DERPMap": derp_map(ctx),
            "DNSConfig": { "Domains": [ctx.dns_domain.clone()] },
            "Domain": ctx.domain.clone(),
            "PacketFilters": { "base": [ {
                "SrcIPs": ["*"],
                "DstPorts": [ { "IP": "*", "Ports": { "First": 0, "Last": 65535 } } ]
            } ] },
            "UserProfiles": [ { "ID": 1, "LoginName": ctx.user, "DisplayName": ctx.user } ],
            "ControlTime": rfc3339(now),
        }),
        compress,
    )
}

/// 增量帧：PeersChanged（全条目 upsert）+ PeersRemoved（同一帧可并存）
pub fn delta_frame(
    changed: &[NodeEntry],
    removed: &[i64],
    ctx: &NetmapCtx,
    now: u64,
    compress: bool,
) -> Vec<u8> {
    let mut v = json!({ "ControlTime": rfc3339(now) });
    if !changed.is_empty() {
        v["PeersChanged"] = Value::Array(changed.iter().map(|p| node_json(p, ctx)).collect());
    }
    if !removed.is_empty() {
        v["PeersRemoved"] = json!(removed);
    }
    frame(&v, compress)
}

/// keepalive 帧（无 peer 字段 = "不变更"，客户端跳过）
pub fn keepalive_frame(now: u64, compress: bool) -> Vec<u8> {
    frame(
        &json!({ "KeepAlive": true, "ControlTime": rfc3339(now) }),
        compress,
    )
}

fn derp_map(ctx: &NetmapCtx) -> Value {
    json!({
        "Regions": {
            ctx.derp_region.to_string(): {
                "RegionID": ctx.derp_region,
                "RegionCode": ctx.derp_hostname,
                "RegionName": "landscape-rill embedded DERP",
                "Nodes": [ {
                    "Name": ctx.derp_region.to_string(),
                    "RegionID": ctx.derp_region,
                    "HostName": ctx.derp_hostname,
                    "DERPPort": ctx.derp_port,
                    "STUNPort": -1,
                } ]
            }
        }
    })
}

/// /key 响应体（headscale 小写字段名；客户端 alias 兼容两者）
pub fn key_response(noise_pub: &[u8; 32]) -> Vec<u8> {
    serde_json::to_vec(&json!({ "publicKey": format!("mkey:{}", hex(noise_pub)) }))
        .expect("key json serializes")
}

/// /machine/register 成功响应（Error 空 + AuthURL 空 = 成功，客户端判定契约）
pub fn register_response_ok(ctx: &NetmapCtx) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "User": {
            "ID": 1, "LoginName": ctx.user, "DisplayName": ctx.user,
            "ProfilePicURL": "", "Roles": null, "LoginProvider": null,
        },
        // Login.ID/UserID 是 Go 侧整型（LoginID），字符串会让官方客户端反序列化失败
        "Login": { "ID": 1, "LoginName": ctx.user, "DisplayName": ctx.user },

        "NodeKeyExpired": false,
        "MachineAuthorized": true,
        "AuthURL": "",
        "Error": "",
    }))
    .expect("register json serializes")
}

/// /machine/register 失败响应（200 + Error 载荷：两类客户端都走 Error 字段判定）
pub fn register_response_err(msg: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "User": { "ID": 1, "LoginName": "", "DisplayName": "" },
        "Login": { "ID": 1, "LoginName": "", "DisplayName": "" },
        "NodeKeyExpired": false, "MachineAuthorized": false, "AuthURL": "", "Error": msg,
    }))
    .expect("register err json serializes")
}

/// early payload（明文经 NoiseStream 写出）：5B magic + 4B BE 长度 + JSON
pub fn early_payload(challenge: &[u8; 32]) -> Vec<u8> {
    // ChallengePublic 线格式 = "chalpub:<hex64>"（官方客户端 UnmarshalText 按前缀裁决，e2e 实证）
    let json =
        serde_json::to_vec(&json!({ "nodeKeyChallenge": format!("chalpub:{}", hex(challenge)) }))
            .expect("early noise json serializes");
    let mut out = Vec::with_capacity(9 + json.len());
    out.extend_from_slice(&[0xff, 0xff, 0xff, b'T', b'S']);
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    out
}

fn hex(bytes: &[u8]) -> String {
    crate::tailcfg::hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> NetmapCtx {
        NetmapCtx {
            user: "ts".into(),
            dns_domain: "lab.ts".into(),
            domain: "lrill-ts".into(),
            derp_region: 1,
            derp_hostname: "lrill-ts".into(),
            derp_port: 8443,
        }
    }

    fn entry(nid: i64, suffix: u32) -> NodeEntry {
        NodeEntry {
            nid,
            machine: [nid as u8; 32],
            node_key: [(nid + 1) as u8; 32],
            disco_key: [7; 32],
            hostname: format!("node{nid}"),
            approved_routes: vec!["10.42.0.0/24".into()],
            announced_routes: vec!["10.42.0.0/24".into()],
            endpoints: vec!["192.0.2.10:41641".into()],
            preferred_derp: None,
            online: true,
            suffix,
            created: 1_800_000_000,
            last_seen: 1_800_000_100,
        }
    }

    #[test]
    fn rfc3339_format() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_800_000_000), "2027-01-15T08:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z"); // 闰日
    }

    #[test]
    fn full_frame_shape() {
        let f = full_frame(&entry(1, 1), &[entry(2, 2)], &ctx(), 1_800_000_200, false);
        // 4B LE 长度前缀
        let len = u32::from_le_bytes(f[..4].try_into().unwrap()) as usize;
        assert_eq!(f.len(), 4 + len);
        let v: Value = serde_json::from_slice(&f[4..]).unwrap();
        for key in [
            "Node",
            "Peers",
            "DERPMap",
            "DNSConfig",
            "Domain",
            "PacketFilters",
            "UserProfiles",
            "ControlTime",
        ] {
            assert!(v.get(key).is_some(), "missing {key}");
        }
        let node = &v["Node"];
        assert_eq!(node["Addresses"][0], "100.64.0.1/32");
        assert_eq!(node["Addresses"][1], "fd7a:115c:a1e0::1/128");
        assert!(node["AllowedIPs"]
            .as_array()
            .unwrap()
            .contains(&json!("10.42.0.0/24")));
        assert_eq!(node["Name"], "node1.ts.lab.ts.");
        let peer = &v["Peers"][0];
        assert_eq!(peer["ID"], 2);
        assert_eq!(peer["Machine"], format!("mkey:{}", hex(&[2u8; 32])));
        // DERPMap 客户端解析路径（tailcfg.derp_node）
        let region = &v["DERPMap"]["Regions"]["1"];
        assert_eq!(region["RegionID"], 1);
        assert_eq!(region["Nodes"][0]["HostName"], "lrill-ts");
        assert_eq!(region["Nodes"][0]["DERPPort"], 8443);
    }

    #[test]
    fn zstd_frame_layout_and_roundtrip_prefix() {
        let json = br#"{"KeepAlive":true}"#;
        let f = zstd_raw_frame(json);
        // RFC 8878：magic + FHD(单段 4B FCS) + 内容长 + Raw block 头 + 原文
        assert_eq!(&f[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
        assert_eq!(f[4], 0xA0);
        assert_eq!(
            u32::from_le_bytes(f[5..9].try_into().unwrap()) as usize,
            json.len()
        );
        let bh = f[9] as u32 | (f[10] as u32) << 8 | (f[11] as u32) << 16;
        assert_eq!(bh >> 3, json.len() as u32); // Block_Size
        assert_eq!((bh >> 1) & 0b11, 0); // Block_Type = Raw
        assert_eq!(bh & 1, 1); // Last_Block
        assert_eq!(&f[12..], json);
        // compress 组帧：4B LE 长度 = zstd 帧长（≠ JSON 长）
        let k = keepalive_frame(0, true);
        let len = u32::from_le_bytes(k[..4].try_into().unwrap()) as usize;
        assert_eq!(k.len(), 4 + len);
        assert_eq!(&k[4..8], &[0x28, 0xB5, 0x2F, 0xFD]);
    }

    #[test]
    fn delta_frame_shape() {
        let f = delta_frame(&[entry(2, 2)], &[5], &ctx(), 0, false);
        let v: Value = serde_json::from_slice(&f[4..]).unwrap();
        assert_eq!(v["PeersChanged"][0]["ID"], 2);
        assert_eq!(v["PeersRemoved"], json!([5]));
        assert!(v.get("Peers").is_none(), "增量帧不带全量 Peers");
    }

    #[test]
    fn key_and_register_responses() {
        assert_eq!(
            String::from_utf8(key_response(&[9u8; 32])).unwrap(),
            format!("{{\"publicKey\":\"mkey:{}\"}}", hex(&[9u8; 32]))
        );
        let ok: Value = serde_json::from_slice(&register_response_ok(&ctx())).unwrap();
        assert_eq!(ok["Error"], "");
        assert_eq!(ok["MachineAuthorized"], true);
        let err: Value = serde_json::from_slice(&register_response_err("bad key")).unwrap();
        assert_eq!(err["Error"], "bad key");
    }

    #[test]
    fn early_payload_layout() {
        let p = early_payload(&[1u8; 32]);
        assert_eq!(&p[..5], &[0xff, 0xff, 0xff, b'T', b'S']);
        let len = u32::from_be_bytes(p[5..9].try_into().unwrap()) as usize;
        assert_eq!(p.len(), 9 + len);
        let v: Value = serde_json::from_slice(&p[9..]).unwrap();
        assert_eq!(
            v["nodeKeyChallenge"],
            format!("chalpub:{}", hex(&[1u8; 32]))
        );
    }
}
