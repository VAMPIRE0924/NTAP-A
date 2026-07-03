# NTAP-A

NTAP-A 是 NTAP 的公网控制端和中继端。它负责节点注册、TAP 用户鉴权、运行配置下发、TAP 二层帧中继、Direct 策略接口，以及后续 Web/API 管理入口。

NTAP 分为三个仓库：

- `NTAP-A`: 公网服务器，管理 API、SQLite 状态库、节点/TAP 鉴权、TapHub 中继。
- `NTAP-B`: OpenWrt/Linux 网关节点，连接 A，创建 TAP，并按 A 下发的配置挂接本地网桥。
- `NTAP-C`: 远端客户机客户端，Windows 端提供图形界面，Linux 端提供命令行客户端。

## 下载和部署

正式部署请下载 GitHub Release 里的编译产物，不要直接拿源码目录里的临时构建文件部署。

最新版本：

https://github.com/VAMPIRE0924/NTAP-A/releases/latest

Linux 服务器优先使用：

```text
NTAP-A-<version>-linux-x64.tar.gz
```

基本流程：

```sh
tar -xzf NTAP-A-<version>-linux-x64.tar.gz
cd NTAP-A-<version>-linux-x64
cp conf/ntap-a.conf.example conf/ntap-a.conf
```

首次运行前请修改配置里的 API key、监听地址、SQLite 数据库路径等参数。

常用命令：

```sh
bin/ntap-a -c conf/ntap-a.conf initdb
bin/ntap-a -c conf/ntap-a.conf serve
bin/ntap-a -c conf/ntap-a.conf api
```

Release 包内带有 systemd 安装脚本，可用于固定目录部署：

```sh
sudo sh install/install-linux-service.sh
sudo sh install/install-linux-service.sh --enable --start
```

## 源码构建

源码仓库只保存 NTAP-A 自身代码和共享协议代码。编译需要 C11 编译器、OpenSSL，NTAP-A 还需要 SQLite。

```sh
make
make config-test
```

Windows/MSYS2 构建主要用于开发验证；生产部署建议使用 Linux Release 包。

## 目录

```text
src/a/       NTAP-A 服务端源码
src/common/  三端共享协议、日志、网络、时间、buffer 等公共代码
conf/        最小配置示例
Makefile     单仓库构建入口
```

## 安全注意

- 对公网暴露 API 前必须修改默认 API key。
- SQLite 数据库和日志路径应放在持久化目录。
- API/Web、TAP 中继、节点连接应按部署环境拆分监听地址和防火墙策略。
- Release 包和源码提交是两条线：源码仓库保持干净，编译产物只放 GitHub Release。
