# P0：headscale + 官方 Tailscale 客户端入网验证
# FROM mesh-e2e-base（已有 iproute2/iputils-ping/ca-certificates），内置 headscale/tailscaled 二进制
# 自签 CA 预装系统信任（tailscale up 校验 headscale TLS 必需，TS2021_LEG §6）
FROM mesh-e2e-base
COPY headscale /usr/local/bin/headscale
COPY tailscale_*/tailscaled /usr/local/bin/tailscaled
COPY tailscale_*/tailscale /usr/local/bin/tailscale
COPY entry-node.sh /usr/local/bin/entry-node.sh
COPY ca.pem /usr/local/share/ca-certificates/p0-ca.crt
RUN chmod +x /usr/local/bin/headscale /usr/local/bin/tailscaled /usr/local/bin/tailscale /usr/local/bin/entry-node.sh \
 && update-ca-certificates
