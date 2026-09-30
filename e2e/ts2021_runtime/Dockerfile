# ts2021 运行时集成 e2e 镜像：lrill（含自研 ts2021 服务端）+ tailscaled 同镜像，按服务分派 command
# FROM tsrt-e2e-base（mesh-e2e-base + iptables，run.sh 预置；DNS 受限环境 apt 需 --dns 引导）
FROM tsrt-e2e-base

COPY lrill /usr/local/bin/lrill
COPY tailscale_*/tailscaled /usr/local/bin/tailscaled
COPY tailscale_*/tailscale /usr/local/bin/tailscale
COPY entry-node.sh entry-rill.sh /usr/local/bin/
# mesh 控制面信任锚（coord 侧）+ ts2021 控制面信任锚（tsrv 侧）
COPY ca.pem /etc/landscape/ca.pem
COPY coord.crt /etc/landscape/coord.crt
COPY coord.key /etc/landscape/coord.key
COPY ts2021-ca.pem /etc/landscape/ts2021-ca.pem
COPY server.crt /etc/landscape/server.crt
COPY server.key /etc/landscape/server.key
# ts2021 CA 预装系统信任（node-c 官方 tailscaled 走系统证书库；lrill 另经配置 CA 显式加载）
COPY ts2021-ca.pem /usr/local/share/ca-certificates/tsrt-ca.crt
RUN chmod +x /usr/local/bin/lrill /usr/local/bin/tailscaled \
                /usr/local/bin/tailscale /usr/local/bin/entry-node.sh /usr/local/bin/entry-rill.sh \
 && update-ca-certificates
