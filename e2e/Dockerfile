# landscape-rill mesh e2e：coordinator + 双节点容器（privileged + /dev/net/tun）
# 构建：宿主编译 release 二进制 → 拷贝进镜像（避免容器内全量编译）
# base 镜像由 run_e2e.sh 预置（环境 DNS 受限，需 --dns 引导 apt）
FROM mesh-e2e-base

COPY lrill /usr/local/bin/lrill
COPY ca.pem /etc/landscape/ca.pem
COPY coord.crt /etc/landscape/coord.crt
COPY coord.key /etc/landscape/coord.key
# config.json 由 compose 按服务挂载（coord / node-a / node-b 各自配置）

ENTRYPOINT ["/usr/local/bin/lrill", "run", "/etc/landscape/overlay.json"]
