# OpenVPN-UI 构建基线测试环境

本目录只用于需求文档“任务 2：建立构建基线”。它不会挂载生产 PKI、证书、SQLite 或 Docker Socket。

## 1. 约束

- 测试服务器：Linux AMD64，地址 `192.168.5.240`。
- 项目目录必须位于 `/opt/openvpn-dev` 下。
- 测试 UI 使用 `192.168.5.240:8081`。
- 测试 OpenVPN UDP 使用 `192.168.5.240:1196`。
- 所有运行数据保存在本目录的 `.runtime`，不得改为 `/opt/openvpn`。
- 不执行 `docker compose down -v`。

## 2. 服务器预检查

```bash
uname -m
docker version
docker compose version
docker buildx version
ss -lntup | grep -E ':(8081|1196)\b' || true
```

预期架构为 `x86_64`，端口 `8081/tcp` 和 `1196/udp` 未被占用。

## 3. 准备固定运行时基座

测试服务器已经存在当前运行的固定 UI 镜像时，只增加独立标签，不覆盖原标签：

```bash
docker image inspect d3vilh/openvpn-server:0.5.5-amd64 --format '{{.Architecture}} {{index .Config.Labels "version"}}'
docker image inspect d3vilh/openvpn-ui:0.9.5.6-amd64 --format '{{.Architecture}} {{index .Config.Labels "version"}}'
docker tag d3vilh/openvpn-ui:0.9.5.6-amd64 zhisuan/openvpn-ui-runtime-base:0.9.5.6-current
```

预期两者架构均为 `amd64`，版本分别为 `0.5.5` 和 `0.9.5.6`。

如果独立测试服务器没有这两个镜像，才可以先导入项目提供的离线包。不要在已有同名生产镜像的服务器上直接执行 `docker load`，避免重写标签。

## 4. 初始化测试配置

```bash
cd openvpn-ui/deploy/dev
cp .env.example .env
chmod 600 .env
```

编辑 `.env`，至少替换 `OPENVPN_ADMIN_PASSWORD`。不得复用生产密码。

```bash
./prepare.sh
docker compose --env-file .env config --quiet
```

`prepare.sh` 只在文件不存在时复制测试模板，不覆盖已有测试 CA、证书或数据库。

## 5. 构建基线镜像

在 `openvpn-ui` 根目录执行：

构建阶段默认使用 Alpine 官方镜像列表中的中科大镜像下载 Go/GCC，APK 软件包仍执行 Alpine 签名校验；可通过 `ALPINE_MIRROR` 构建参数替换。

```bash
docker buildx build \
  --pull=false \
  --provenance=false \
  --platform linux/amd64 \
  --load \
  --build-arg APP_VERSION=0.9.5.6 \
  --build-arg VCS_REF=d4b96c7ae344042cd3d7f059c100c0646f8a3c4d \
  -t zhisuan/openvpn-ui:baseline \
  .
```

检查镜像：

```bash
docker image inspect zhisuan/openvpn-ui:baseline --format '{{.Architecture}} {{index .Config.Labels "version"}} {{index .Config.Labels "org.opencontainers.image.revision"}}'
```

## 6. 启动测试环境

```bash
cd deploy/dev
docker compose --env-file .env up -d
docker compose --env-file .env ps
```

首次启动会生成测试 CA 和服务器证书，可能需要等待数分钟。UI 健康后访问：

```text
http://192.168.5.240:8081
```

## 7. 基线验收

依次验证：

1. 使用 `.env` 中的测试管理员登录；
2. 证书列表正常打开；
3. 创建名称唯一的测试证书；
4. 启用 2FA 后二维码能正常显示；
5. `.ovpn` 文件可以下载；
6. 首页在线状态可读取 `openvpn:2080`，无连接时显示空列表。

上游 `0.9.5.6` 会把测试 2FA URI/Secret 写入容器日志，这是已知基线缺陷。本阶段只使用测试数据且不要复制相关日志；后续 2FA 任务再修复。

测试环境未挂载 Docker Socket，因此页面上的容器重启按钮不属于本阶段验收范围。

## 8. 停止与回滚

```bash
docker compose --env-file .env down
```

该命令停止并移除本测试项目的容器和网络，但保留 `.runtime` 测试数据。需要重新初始化时，先停止容器，再将 `.runtime` 重命名为备份目录，不要直接删除。
