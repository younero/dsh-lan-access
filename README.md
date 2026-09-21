# dsh-lan-access

一个只做局域网端口转发的 dsh 插件。dsh 继续监听 `127.0.0.1`，插件在局域网地址上开启带密钥的 HTTP/WebSocket 中继，因此手机或同一局域网的其他电脑可以访问当前这次 `dsh web`。插件会额外注入一小段兼容代码，让 dsh 把转发过来的页面仍视为当前本机 harness，否则工作区和设置会显示为空。

## 安装

从 npm 安装：

```bash
dsh plugin --profile web add @lieliefengzhong/dsh-lan-access
```

本地开发安装：

```bash
dsh plugin --profile web add /home/zhuyongchun/codes/dsh-lan-access
```

插件默认加入 profile，但转发默认关闭。启动器也可以直接叠加 patch：

```bash
dsh --profile web --patch /home/zhuyongchun/codes/dsh-lan-access/cordis.patch.yml --no-open
```

## 配置

在 profile 的 `cordis.patch.yml` 中按 id 覆盖配置：

```yaml
- id: dsh-lan-access
  config:
    enabled: true
    host: 0.0.0.0
    port: 8790
    # 不填则每次启动随机生成密钥并打印访问链接
    # token: 'your-strong-static-key'
    sessionTtlMs: 2592000000
    # true 时拒绝设置、凭据、目录选择和模型探测等高风险 RPC
    blockPrivileged: false
```

启动后终端会打印类似：

```text
dsh-lan-access: 手机访问入口: http://192.168.1.23:8790/?k=<访问密钥>
```

手机和电脑在同一局域网时打开这个链接即可。密钥会换成签名 cookie，HTTP 请求和 WebSocket 升级都会转发到当前 dsh Web 服务，工作区和会话保持一致。

将 `blockPrivileged` 设为 `true` 可以进一步限制手机端权限，但手机端将不能修改 DSH 设置、管理凭据、选择本机目录或探测模型。

## 安全说明

`/api` 可以驱动 dsh 的 agent、bash 和文件工具，相当于在电脑上执行命令。中继只适用于可信局域网；不要直接暴露到公网。需要跨公网访问时，请在这个 loopback 服务外面使用 Tailscale Serve、Cloudflare Tunnel 等带身份认证的隧道。

## 测试

```bash
npm test
```
