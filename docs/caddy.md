# Caddy 反向代理

面板自身使用 HTTPS。如果服务器已有 Caddy 域名，可以把它挂载到 `/incus/`，同时保留原站点：

```caddyfile
example.com {
  handle_path /incus/* {
    reverse_proxy https://127.0.0.1:8443 {
      transport http {
        tls_insecure_skip_verify
      }
    }
  }

  handle {
    reverse_proxy 127.0.0.1:8787
  }
}
```

修改前先备份配置，然后验证并重载：

```bash
sudo cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

访问地址为 `https://example.com/incus/`。`tls_insecure_skip_verify` 只作用于 Caddy 到本机面板的回环连接；浏览器到 Caddy 仍使用域名的受信任证书。
