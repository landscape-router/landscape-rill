# ts2021 注册 e2e：headscale + lrill ts2021-register 探针 + 官方 tailscaled
# FROM mesh-e2e-base（已有 iproute2/iputils-ping/ca-certificates），内置 headscale/tailscaled 二进制
# 自签 CA 预装系统信任（双保险：lrill 另经 --ca 显式加载）
FROM mesh-e2e-base
COPY headscale /usr/local/bin/headscale
COPY tailscale_*/tailscaled /usr/local/bin/tailscaled
COPY tailscale_*/tailscale /usr/local/bin/tailscale
COPY entry-node.sh /usr/local/bin/entry-node.sh
COPY entry-lrill.sh /usr/local/bin/entry-lrill.sh
COPY ts2021-register /usr/local/bin/ts2021-register
COPY ca.pem /usr/local/share/ca-certificates/ts2021-ca.crt
RUN chmod +x /usr/local/bin/headscale /usr/local/bin/tailscaled /usr/local/bin/tailscale \
 && chmod +x /usr/local/bin/entry-node.sh /usr/local/bin/entry-lrill.sh /usr/local/bin/ts2021-register \
 && update-ca-certificates
