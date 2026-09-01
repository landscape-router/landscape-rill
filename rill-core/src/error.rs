use serde::{Deserialize, Serialize};

/// 构建 args JSON 对象（宏生成的 error_args 使用，ERROR_ID §3.2）
pub fn args(pairs: &[(&str, String)]) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for (k, v) in pairs {
        m.insert((*k).to_string(), serde_json::Value::String(v.clone()));
    }
    serde_json::Value::Object(m)
}

/// error_args 的返回类型（serde_json::Value 的别名，避免消费方依赖 serde_json）
pub type ErrorArgs = serde_json::Value;

/// 序列化错误信封（ERROR_ID §4）：稳定 id + 插值参数 + 人类可读消息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorEnvelope {
    pub id: String,
    pub args: serde_json::Value,
    pub message: String,
}

/// 所有错误类型实现该 trait，提供稳定 error_id 供客户端 i18n 翻译
/// （ERROR_ID §3）。实现由 `#[derive(ErrorId)]` 生成（见 rill-macro）。
pub trait ErrorId {
    fn error_id(&self) -> &'static str;

    /// 翻译插值参数（如 `{"0": "10.0.0.0/8"}`）
    fn error_args(&self) -> ErrorArgs;

    /// 对外安全消息，默认 Display；敏感内部细节可覆盖隐藏
    fn to_public_message(&self) -> String
    where
        Self: std::fmt::Display,
    {
        self.to_string()
    }

    /// 序列化信封（id + args + message）
    fn to_envelope(&self) -> ErrorEnvelope
    where
        Self: std::fmt::Display,
    {
        ErrorEnvelope {
            id: self.error_id().to_string(),
            args: self.error_args(),
            message: self.to_public_message(),
        }
    }
}

/// 展开错误 source 链为单行可读文本（日志用，ERROR_ID §2.3；`{e}` 只打顶层 Display）
pub fn format_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(s) = cur {
        out.push_str(": ");
        out.push_str(&s.to_string());
        cur = s.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error, landscape_rill_macro::ErrorId)]
    #[error_id(crate_path = "crate")]
    enum TestError {
        #[error("route {0} invalid")]
        #[error_id("test.invalid_route")]
        InvalidRoute(String),
        #[error("crypto failure")]
        #[error_id("test.crypto")]
        Crypto,
    }

    #[test]
    fn envelope_carries_id_args_message() {
        let e = TestError::InvalidRoute("10.0.0.0/8".to_string());
        let env = e.to_envelope();
        assert_eq!(env.id, "test.invalid_route");
        assert_eq!(env.args["0"], "10.0.0.0/8");
        assert_eq!(env.message, "route 10.0.0.0/8 invalid");

        let env = TestError::Crypto.to_envelope();
        assert_eq!(env.id, "test.crypto");
        assert_eq!(env.args, serde_json::json!({}));
    }

    #[derive(Debug, thiserror::Error, landscape_rill_macro::ErrorId)]
    #[error_id(crate_path = "crate")]
    enum OuterError {
        #[error(transparent)]
        #[error_id(transparent)]
        Inner(#[from] TestError),
    }

    #[test]
    fn transparent_delegates_metadata() {
        let e = OuterError::from(TestError::InvalidRoute("10.0.0.0/8".to_string()));
        let env = e.to_envelope();
        assert_eq!(env.id, "test.invalid_route");
        assert_eq!(env.args["0"], "10.0.0.0/8");
    }

    #[derive(Debug, thiserror::Error)]
    enum ChainInner {
        #[error("inner failed")]
        Inner,
    }

    #[derive(Debug, thiserror::Error)]
    enum ChainOuter {
        #[error("outer failed")]
        Outer(#[from] ChainInner),
    }

    #[test]
    fn format_chain_expands_sources() {
        let e = ChainOuter::from(ChainInner::Inner);
        assert_eq!(format_chain(&e), "outer failed: inner failed");
    }
}
