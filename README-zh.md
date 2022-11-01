[English](README.md) | [中文](README-zh.md) | [Vídeo en Español](https://www.youtube.com/watch?v=99qtaJU2E2k)

# WireGuard VPN 服务器 中文一键安装脚本

[![Build Status](https://github.com/hwdsl2/wireguard-install/actions/workflows/main.yml/badge.svg)](https://github.com/hwdsl2/wireguard-install/actions/workflows/main.yml) &nbsp;[![License: MIT](docs/images/license.svg)](https://opensource.org/licenses/MIT)

使用 Linux 脚本一键快速搭建自己的 WireGuard VPN 服务器。支持 Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS 和 Fedora。

该脚本可让你在几分钟内建立自己的 VPN 服务器，即使你以前没有使用过 WireGuard。[WireGuard](https://www.wireguard.com) 是一种快速且现代的 VPN，其设计目标是易于使用和高性能。

[**&raquo; 另见：OpenVPN 服务器一键安装脚本**](https://github.com/hwdsl2/openvpn-install/blob/master/README-zh.md)

## 功能特性

- 全自动的 WireGuard VPN 服务器配置，无需用户输入
- 支持使用自定义选项进行交互式安装
- 生成 VPN 配置文件以自动配置 Windows, macOS, iOS 和 Android 设备
- 支持管理 WireGuard VPN 用户
- 优化 `sysctl` 设置以提高 VPN 性能

## 安装说明

首先在你的 Linux 服务器\* 上下载脚本：

```bash
wget -O wireguard.sh https://get.vpnsetup.net/wg
```

**选项 1:** 使用默认选项自动安装 WireGuard。

```bash
sudo bash wireguard.sh --auto
```

<details>
<summary>
查看脚本的示例输出（终端记录）。
</summary>

**注：** 此终端记录仅用于演示目的。

<p align="center"><img src="docs/images/demo1.svg"></p>
</details>

对于有外部防火墙的服务器（比如 [EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)/[GCE](https://cloud.google.com/vpc/docs/firewalls)），请为 VPN 打开 UDP 端口 51820。

**选项 2:** 使用自定义选项进行交互式安装。

```bash
sudo bash wireguard.sh
```

<details>
<summary>
如果无法下载，请点这里。
</summary>

你也可以使用 `curl` 下载：

```bash
curl -fL -o wireguard.sh https://get.vpnsetup.net/wg
```

然后按照上面的说明安装。

或者，你也可以使用这些链接：

```bash
https://github.com/hwdsl2/wireguard-install/raw/master/wireguard-install.sh
https://gitlab.com/hwdsl2/wireguard-install/-/raw/master/wireguard-install.sh
```

如果无法下载，打开 [wireguard-install.sh](wireguard-install.sh)，然后点击右边的 `Raw` 按钮。按快捷键 `Ctrl/Cmd+A` 全选，`Ctrl/Cmd+C` 复制，然后粘贴到你喜欢的编辑器。
</details>

\* 一个云服务器，虚拟专用服务器 (VPS) 或者专用服务器。

## 下一步

安装完成后，你可以再次运行脚本来管理用户或者卸载 WireGuard。

配置你的计算机或其它设备使用 VPN。请参见：

**[配置 WireGuard VPN 客户端](docs/clients-zh.md)**

**[下载 VPN 文档的 PDF 版本（支持者）](https://ko-fi.com/post/Support-this-project-and-get-access-to-supporter-o-X8X5FVFZC)**

开始使用自己的专属 VPN! :sparkles::tada::rocket::sparkles:

<details>
<summary>
如果你喜欢这个项目，可以表达你的支持或感谢。
</summary>

<a href="https://ko-fi.com/hwdsl2" target="_blank"><img height="36" width="187" src="docs/images/kofi2.png" border="0" alt="Buy Me a Coffee at ko-fi.com" /></a> &nbsp;&nbsp;<a href="https://coindrop.to/hwdsl2" target="_blank"><img src="docs/images/embed-button.png" height="36" width="145" border="0" alt="Coindrop.to me" /></a>

仅限支持者的内容可用。[点击查看详情](https://ko-fi.com/post/Support-this-project-and-get-access-to-supporter-o-X8X5FVFZC)。
</details>

## 致谢

此脚本基于 [Nyr 和 contributors](https://github.com/Nyr/wireguard-install) 的出色工作，并进行了增强和更改以与 [Setup IPsec VPN](https://github.com/hwdsl2/setup-ipsec-vpn) 项目兼容。

<details>
<summary>
对 Nyr/wireguard-install 的改进列表。
</summary>

- 改进了与 Setup IPsec VPN 的兼容性
- 改进了脚本的可靠性，用户输入和输出
- 支持使用默认选项自动安装
- 支持列出现有的 VPN 客户端
- 支持为 VPN 客户端自定义 DNS 服务器
- 优化 `sysctl` 设置以提高 VPN 性能
- 使用 `sudo` 时改进了客户端配置文件的创建

...和更多！
</details>

## 授权协议

MIT
