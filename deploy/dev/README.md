# OpenVPN-UI 构建基线测试环境

本目录只用于需求文档“任务 2：建立构建基线”。它不会挂载生产 PKI、证书、SQLite 或 Docker Socket。

## 1. 约束

- 测试服务器：Linux AMD64，地址 `192.168.5.240`。
- 项目目录必须位于 `/opt/openvpn-dev` 下。
- 测试 UI 使用 `192.168.5.240:8081`。
- 测试 OpenVPN UDP 使用 `192.168.5.240:1196`。
- 所有运行数据保存在本目录的 `.runtime`，不得改为 `/opt/openvpn`。
- 不执行 `docker compose down -v`。
- 不访问或修改生产 `8080`、`1195/UDP`、生产 PKI、生产数据库和生产客户端目录。

## 2. 连接测试服务器

本机使用专用私钥连接：

```bash
chmod 600 ~/.ssh/vpn_test_240
ssh -i ~/.ssh/vpn_test_240 -o IdentitiesOnly=yes root@192.168.5.240
```

也可以在本机 `~/.ssh/config` 中配置别名：

```sshconfig
Host vpn-test-240
  HostName 192.168.5.240
  User root
  IdentityFile ~/.ssh/vpn_test_240
  IdentitiesOnly yes
```

配置后使用 `ssh vpn-test-240`。不得读取、输出、复制或记录私钥内容，也不得把测试密码写入本文档。

## 3. 服务器预检查

```bash
uname -m
docker version
docker compose version
docker buildx version
ss -lntup | grep -E ':(8081|1196)\b' || true
timedatectl show -p NTPSynchronized --value
```

首次部署前预期架构为 `x86_64`，端口 `8081/tcp` 和 `1196/udp` 未被占用。环境已经运行时，应先确认占用者是本测试项目，不得直接停止未知服务。

## 4. 2026-07-27 当前环境快照

- 隔离项目运行目录：`/opt/openvpn-dev/zhisuan-vpn-console/openvpn-ui/deploy/dev`。
- 远端部署目录不包含 `.git`，不得在服务器上直接执行 `git pull`。
- UI `8081/tcp` 和 OpenVPN `1196/udp` 正常运行，NTP 已同步。
- 当前 UI 镜像：`zhisuan/openvpn-ui:p0-user-ip-a26195d`，修订为 `a26195d007e1704405840f9b9aa100bebc244e58`。
- 当前 UI 尚未包含阶段 A TOTP 管理功能；数据库文件的非输出表名特征检查未发现 Migration v6 表 `totp_reset_operations`。
- UI 到 OpenVPN Management Interface `openvpn:2080` 可达。
- OpenVPN 版本为 `2.6.12`，尚未启用 `auth-user-pass-verify`；客户端模板尚无 `auth-user-pass`。
- 实际认证脚本存在模糊匹配和敏感日志风险，当前不得启用动态验证码认证。
- 测试 `oath.secrets` 权限为 `0644`；3 个二维码文件权限均不是 `0600`，启用前必须修正。
- 3 张有效测试客户端证书的 PKI Subject 元数据均缺少 `2FAName`。
- 按安全限制未读取 `oath.secrets` 内容，因此 TFA Name 覆盖率、格式和重复情况尚未核实。
- 测试隧道使用 `10.250.70.0/24`，Server 路由为 `10.250.71.0/24`；现有一个静态客户端使用 `10.9.5.0/24` 地址，但没有对应 Server 路由和 `OVPN_GUEST_POLICY`。

以上仅为只读快照。当前远端状态不满足直接执行阶段 B 的条件。

## 5. 准备固定运行时基座

测试服务器已经存在当前运行的固定 UI 镜像时，只增加独立标签，不覆盖原标签：

```bash
docker image inspect d3vilh/openvpn-server:0.5.5-amd64 --format '{{.Architecture}} {{index .Config.Labels "version"}}'
docker image inspect d3vilh/openvpn-ui:0.9.5.6-amd64 --format '{{.Architecture}} {{index .Config.Labels "version"}}'
docker tag d3vilh/openvpn-ui:0.9.5.6-amd64 zhisuan/openvpn-ui-runtime-base:0.9.5.6-current
```

预期两者架构均为 `amd64`，版本分别为 `0.5.5` 和 `0.9.5.6`。

如果独立测试服务器没有这两个镜像，才可以先导入项目提供的离线包。不要在已有同名生产镜像的服务器上直接执行 `docker load`，避免重写标签。

## 6. 初始化测试配置

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

## 7. 构建 UI 镜像

在 `openvpn-ui` 根目录执行：

构建阶段默认使用 Alpine 官方镜像列表中的中科大镜像下载 Go/GCC，APK 软件包仍执行 Alpine 签名校验；可通过 `ALPINE_MIRROR` 构建参数替换。

```bash
docker buildx build \
  --pull=false \
  --provenance=false \
  --platform linux/amd64 \
  --load \
  --build-arg APP_VERSION=0.9.5.6 \
  --build-arg VCS_REF=a1111cb11eb2d78d2915f74175a40ef4a4bd4027 \
  -t zhisuan/openvpn-ui:p0-totp-a1111cb \
  .
```

检查镜像：

```bash
docker image inspect zhisuan/openvpn-ui:p0-totp-a1111cb --format '{{.Architecture}} {{index .Config.Labels "version"}} {{index .Config.Labels "org.opencontainers.image.revision"}}'
```

构建前必须确认本地 `develop` 与 `origin/develop` 同步。若 HEAD 已经更新，应同时更新 `VCS_REF` 和镜像标签，不得继续复用上述旧修订标签。

## 8. 启动测试环境

```bash
cd deploy/dev
docker compose --env-file .env up -d
docker compose --env-file .env ps
```

首次启动会生成测试 CA 和服务器证书，可能需要等待数分钟。UI 健康后访问：

```text
http://192.168.5.240:8081
```

UI 健康不代表测试 PKI 已初始化完成。创建测试证书前还要确认：

```bash
test -f .runtime/pki/index.txt
```

## 9. 基线验收

依次验证：

1. 使用 `.env` 中的测试管理员登录；
2. 证书列表正常打开；
3. 创建名称唯一的测试证书；
4. 启用 2FA 后二维码能正常显示；
5. `.ovpn` 文件可以下载；
6. 首页在线状态可读取 `openvpn:2080`，无连接时显示空列表。

远端当前旧镜像可能把测试 2FA 敏感信息写入容器日志。只允许使用合成测试数据，不得查看、复制或转存相关敏感日志；阶段 A 镜像部署后还需执行只返回通过/失败的日志扫描。

测试环境未挂载 Docker Socket，因此页面上的容器重启按钮不属于本阶段验收范围。

## 10. 阶段 B 启用前门槛

1. 先部署并验收阶段 A UI 和 Migration v6，不重启 OpenVPN。
2. 单独确认安全的 Server 认证脚本或 Server 镜像方案。
3. 经明确授权后，用不回传敏感内容的受控方法核实 TOTP 身份覆盖率。
4. 将 `oath.secrets` 和二维码权限收紧到 `0600`，并核实属主和回滚。
5. 明确使用普通测试用户，还是另行处理 `10.9.5.0/24` 与当前隔离路由不一致的问题。
6. 完成备份、配置差异检查和回滚演练后，才可申请重启隔离 OpenVPN。

任何一项未完成，都不得启用全局 `auth-user-pass-verify`。

## 11. 停止与回滚

```bash
docker compose --env-file .env down
```

该命令停止并移除本测试项目的容器和网络，但保留 `.runtime` 测试数据。需要重新初始化时，先停止容器，再将 `.runtime` 重命名为备份目录，不要直接删除。

只更新 UI 时，应先备份测试数据库和 TOTP 相关测试文件，再仅重建 UI 服务。不要使用 `down -v`，不要删除测试 PKI 历史，也不要修改生产目录。
