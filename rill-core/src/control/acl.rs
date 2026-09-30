//! ACL 策略模型与前缀级裁决（REQ-045，CONTROL_PLANE §3.10）。
//!
//! 有序规则列表 first-match-wins：subject（node:<id> / group:<name> / any）
//! → object（前缀）→ action（allow/deny）。`enabled=false` = v1 全放行；
//! 开启后未匹配即拒（default-deny）。裁决点 = 目标节点解密后（AEAD 会话
//! 即源认证，`from_node_id` 不可冒充，直连/中继/多跳全覆盖，CN-04）；
//! 本模块只做纯函数裁决，I/O-free（同 registry 哲学）。

use crate::route::Prefix;
use std::collections::HashMap;
use std::net::IpAddr;

/// 能力位：支持 ACL 策略裁决（CONTROL_PLANE §3.1；网络开启 ACL 后
/// 无该位的节点注册被拒——防最弱环节绕过，fail-closed）
pub const CAPABILITY_ACL: u32 = 0x40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclSubject {
    Any,
    Node(u32),
    Group(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule {
    pub subjects: Vec<AclSubject>,
    pub prefix: Prefix,
    pub action: AclAction,
}

/// 网络级策略（coordinator 权威，随 netmap 原子下发，version 一版本两用）
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AclPolicy {
    pub enabled: bool,
    pub rules: Vec<AclRule>,
    /// 组 = 管理面标签（config 给 node_id 打标，策略引用；线格式随规则字符串走）
    pub groups: HashMap<String, Vec<u32>>,
}

impl AclPolicy {
    /// 主体命中：any 全匹配；node 精确；group 按标签成员（未知组不匹配任何主体）
    fn subject_matches(&self, subject: &AclSubject, from: u32) -> bool {
        match subject {
            AclSubject::Any => true,
            AclSubject::Node(id) => *id == from,
            AclSubject::Group(name) => self
                .groups
                .get(name)
                .is_some_and(|members| members.contains(&from)),
        }
    }

    /// 前缀级裁决：有序规则 first-match-wins，未匹配 = 拒（default-deny）。
    /// disabled = v1 全放行
    pub fn allows(&self, from: u32, dst: &IpAddr) -> bool {
        if !self.enabled {
            return true;
        }
        for rule in &self.rules {
            if rule.prefix.matches(dst)
                && rule.subjects.iter().any(|s| self.subject_matches(s, from))
            {
                return rule.action == AclAction::Allow;
            }
        }
        false
    }

    /// 数据帧裁决（目标节点解密后入口）：从内层 IP 包提取目的地址；
    /// 非 IP 载荷无法提取目标 = 拒（fail-closed，CONTROL_PLANE §3.10）
    pub fn allows_packet(&self, from: u32, payload: &[u8]) -> bool {
        if !self.enabled {
            return true;
        }
        match packet_dst(payload) {
            Some(dst) => self.allows(from, &dst),
            None => false,
        }
    }
}

/// 内层包目的地址（IPv4 offset 16 / IPv6 offset 24；版本高半字节判族）
fn packet_dst(payload: &[u8]) -> Option<IpAddr> {
    match payload.first()? >> 4 {
        4 => {
            let octets: [u8; 4] = payload.get(16..20)?.try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        6 => {
            let octets: [u8; 16] = payload.get(24..40)?.try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v4_packet(dst: &str) -> Vec<u8> {
        let mut p = vec![0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(
            &ip(dst)
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .unwrap()
                .octets(),
        );
        p
    }

    #[test]
    fn disabled_allows_all() {
        // enabled=false = v1 行为（即使携带规则也不裁决）
        let policy = AclPolicy {
            enabled: false,
            rules: vec![AclRule {
                subjects: vec![AclSubject::Any],
                prefix: Prefix::parse("10.0.0.0/8").unwrap(),
                action: AclAction::Deny,
            }],
            groups: HashMap::new(),
        };
        assert!(policy.allows(1, &ip("10.1.2.3")));
        assert!(policy.allows_packet(1, &v4_packet("10.1.2.3")));
    }

    #[test]
    fn enabled_no_rules_denies_all() {
        let policy = AclPolicy {
            enabled: true,
            ..Default::default()
        };
        assert!(!policy.allows(1, &ip("192.0.2.1")));
    }

    #[test]
    fn first_match_wins_overlapping_rules() {
        // 更窄的 allow 排在更宽的 deny 之前 → 命中即停
        let policy = AclPolicy {
            enabled: true,
            rules: vec![
                AclRule {
                    subjects: vec![AclSubject::Node(2)],
                    prefix: Prefix::parse("10.42.0.0/24").unwrap(),
                    action: AclAction::Allow,
                },
                AclRule {
                    subjects: vec![AclSubject::Any],
                    prefix: Prefix::parse("10.0.0.0/8").unwrap(),
                    action: AclAction::Deny,
                },
            ],
            groups: HashMap::new(),
        };
        assert!(policy.allows(2, &ip("10.42.0.1")));
        assert!(!policy.allows(2, &ip("10.43.0.1"))); // 落到宽 deny
        assert!(!policy.allows(3, &ip("10.42.0.1"))); // 主体不命中窄 allow → 宽 deny
    }

    #[test]
    fn group_and_any_subjects() {
        let mut groups = HashMap::new();
        groups.insert("admins".to_string(), vec![1, 2]);
        let policy = AclPolicy {
            enabled: true,
            rules: vec![AclRule {
                subjects: vec![AclSubject::Group("admins".into()), AclSubject::Node(9)],
                prefix: Prefix::parse("fd00::/8").unwrap(),
                action: AclAction::Allow,
            }],
            groups,
        };
        assert!(policy.allows(1, &ip("fd00:2::1")));
        assert!(policy.allows(9, &ip("fd00:2::1")));
        assert!(!policy.allows(3, &ip("fd00:2::1")));
        // 未知组 = 无成员，不匹配任何主体（fail-closed 方向）
        let unknown = AclPolicy {
            enabled: true,
            rules: vec![AclRule {
                subjects: vec![AclSubject::Group("nobody".into())],
                prefix: Prefix::parse("0.0.0.0/0").unwrap(),
                action: AclAction::Allow,
            }],
            groups: HashMap::new(),
        };
        assert!(!unknown.allows(1, &ip("10.0.0.1")));
    }

    #[test]
    fn non_ip_packet_denied_when_enabled() {
        // 非 IP 载荷无法提取目标 → fail-closed
        let policy = AclPolicy {
            enabled: true,
            rules: vec![AclRule {
                subjects: vec![AclSubject::Any],
                prefix: Prefix::parse("0.0.0.0/0").unwrap(),
                action: AclAction::Allow,
            }],
            groups: HashMap::new(),
        };
        assert!(policy.allows_packet(1, &v4_packet("10.0.0.1")));
        assert!(!policy.allows_packet(1, &[0xaa, 0xbb, 0xcc]));
        assert!(!policy.allows_packet(1, &[]));
        // 短包（版本位 v4 但不足 20B）同样拒
        assert!(!policy.allows_packet(1, &[0x45, 0, 0, 0]));
    }

    #[test]
    fn ipv6_packet_dst_extraction() {
        let mut p = vec![0x60u8; 24];
        p.extend_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let policy = AclPolicy {
            enabled: true,
            rules: vec![AclRule {
                subjects: vec![AclSubject::Any],
                prefix: Prefix::parse("fd00::/8").unwrap(),
                action: AclAction::Allow,
            }],
            groups: HashMap::new(),
        };
        assert!(policy.allows_packet(1, &p));
    }
}
