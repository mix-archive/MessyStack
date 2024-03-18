# MessyStack

Deployment stack for a vulnerable proxy server setup. (DubheCTF 2024 "authenticated mess & unauthenticated less" challenge)

## 题面

给出一个 [`pcapng` 文件](./challenge.pcapng)，其中包含了一些网络流量。参赛者需要分析流量，来对题目中的代理服务器进行攻击。

### 题目描述

> How can things go wrong when using a proxy server?

<details>

<summary>Hints</summary>

> 1. 压缩包加密无需破解，请注意图片的出处和文件命名。
> 2. 此题目后半部分更多偏向于 Web 方向。
> 3. 流量解密后的唯一有效信息就是图片链接，之后的内容无需继续关注。
> 4. 如果阅读流量相关的解密代码对你来说比较困难，不妨试试重放。

</details>

## Writeup

### 分析流量

使用 Wireshark 来打开文件，我们可以看到有一个明文的 HTTP 请求：

```http
GET /raw/sw2TFBLK HTTP/1.1
Host: pastebin.com
User-Agent: curl/8.5.0
Accept: */*
```

访问 <https://pastebin.com/raw/sw2TFBLK> 可以得到一个配置文件：

```json
{
  "log": {
    "loglevel": "debug"
  },
  "inbounds": [
    {
      "port": 1080, // SOCKS 代理端口，在浏览器中需配置代理并指向这个端口
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "1.95.11.7", // 服务器地址，请修改为你自己的服务器 ip 或域名
            "port": 40086, // 服务器端口
            "users": [
              {
                "id": "f3a5cae3-6bd2-40d1-b13b-2cc3d87af2c7",
                "security": "auto"
              }
            ]
          }
        ]
      }
    }
  ]
}
```

可以看到，这是一个 V2Ray 的配置文件。此时我们可以猜测，流量文件后半部分的内容可能是 `VMess` 协议的流量。

### 解密流量

这道题由于[强网杯 2022](https://tttang.com/archive/1687/) 已经出现过对 VMessMD5 的解密手段，所以在出题时专门采用了更新的 VMessAEAD 的加密方式（也是现在版本的 v2ray-core 强制的加密方式）。

> [!IMPORTANT]
> VMessMD5 被弃用的原因是因为它能够被很容易地通过主动探测的手段检测到，见 [v2ray-core#2523](https://github.com/v2ray/v2ray-core/issues/2523)

解密流量有两种方法，一种是通过阅读代码来自己实现解密，另一种是通过重放流量来获取明文。

> [!NOTE]
> 关于协议的部分实现，可以参考 [extra-VMessAEADdoc.zip](https://github.com/v2fly/v2ray-core/releases/download/v4.24.1/extra-VMessAEADdoc.zip)
> 但是协议的最终实现还是需要参考 v2ray-core 的源码，因为有些地方的实现和文档中的描述不一致。

在这里我[写了一个库](https://github.com/mnixry/vmess-aead-python)专门用来解析 VMessAEAD 的流量。

```python
import uuid

from vmess_aead.encoding import VMessBodyEncoder
from vmess_aead.headers.request import VMessAEADRequestPacketHeader
from vmess_aead.utils.reader import BytesReader

data = "a49502ee07ffdd20f11597e961f7768b41be7bc32030107fc81f235f72ff1b294d074ade94281242412b4c19123b15250ac3d5ad9524df9acd0ee5f6dcca7b0c2849b2f4df20190dd084c01c3f6e2834dd87cb8e97fa178b2ec454755f89d9b735ae6dab9c7989cf4154f7eae53774d9d6cdb55d0a76fdaf21e08bae26e49cbb3c56d11a3fe540454bfbae06305460301caca4109df3335b0c3646b6e2d856a927f9298b87da3a7cf3cffcca6c27259fc055faa9f3155cc95f698bb37436008783b6cd03d38a8e109f78a48c860b600fcbe825cd6c6a5be2c95fce121df574c70fe62e4f24e28de5983db6c3c0192d72ec785b6d58c4b8301c4f70eab683"
data = bytes.fromhex(data)

reader = BytesReader(data)
user_id = uuid.UUID("f3a5cae3-6bd2-40d1-b13b-2cc3d87af2c7")


header = VMessAEADRequestPacketHeader.from_packet(reader, user_id)
print(header)

encoder = VMessBodyEncoder(
    header.payload.body_key,
    header.payload.body_iv,
    header.payload.options,
    header.payload.security,
    header.payload.command,
)
body = encoder.decode_once(reader)
print(body)
```

在比赛中，重放流量应当是更加简单的方法。

> [!TIP]
> 因为 VMessAEAD 并没有类似于 VMessMD5 那样的[请求头时间戳爆破机制](https://www.v2fly.org/developer/protocols/vmess.html#%E5%AE%A2%E6%88%B7%E7%AB%AF%E8%AF%B7%E6%B1%82)，只有检查根据 UUID 最终解密后的结果中时间戳是否在合理范围内的机制。所以重放流量是行得通的，[只需要 Patch 掉对时间范围的检查即可](https://github.com/v2fly/v2ray-core/blob/49b5068606f5c764dcdf65854565b1b9c8abb292/proxy/vmess/aead/authid.go#L108-L110)。

流量解密后，我们能得到一个图片的链接：

![玩BA玩的](http://p.sda1.dev/16/11c111ee40a928d5d751dd5869414093/__p0.png)

### 图片解压

这张图片是一个压缩包和一张图片的合成图。我们可以使用 `binwalk` 来看到其中的文件：

```bash
$ binwalk __p0.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 2240 x 3272, 8-bit/color RGB, non-interlaced
62            0x3E            Zlib compressed data, default compression
1487451       0x16B25B        Zip archive data, encrypted compressed size: 28, name: .vscode/
1487528       0x16B2A8        Zip archive data, encrypted compressed size: 89, uncompressed size: 63, name: .vscode/settings.json
1487679       0x16B33F        Zip archive data, encrypted compressed size: 28, name: docker/
1487755       0x16B38B        Zip archive data, encrypted compressed size: 321, uncompressed size: 434, name: docker/Dockerfile
1488134       0x16B506        Zip archive data, encrypted compressed size: 284, uncompressed size: 513, name: docker/docker-compose.yml
1488484       0x16B664        Zip archive data, encrypted compressed size: 299, uncompressed size: 527, name: docker/v2ray-config.json
1488848       0x16B7D0        Zip archive data, encrypted compressed size: 28, name: src/
1488921       0x16B819        Zip archive data, encrypted compressed size: 9554, uncompressed size: 31864, name: src/index.js
1498528       0x16DDA0        Zip archive data, encrypted compressed size: 72, uncompressed size: 46, name: .dockerignore
1498654       0x16DE1E        Zip archive data, encrypted compressed size: 1009, uncompressed size: 2131, name: .gitignore
1499714       0x16E242        Zip archive data, encrypted compressed size: 80, uncompressed size: 63, name: .prettierrc
1499846       0x16E2C6        Zip archive data, encrypted compressed size: 261, uncompressed size: 337, name: healthcheck.js
1500162       0x16E402        Zip archive data, encrypted compressed size: 12134, uncompressed size: 35149, name: LICENSE
1512344       0x171398        Zip archive data, encrypted compressed size: 181, uncompressed size: 255, name: package.json
1512578       0x171482        Zip archive data, encrypted compressed size: 9647, uncompressed size: 26002, name: pnpm-lock.yaml
1522280       0x173A68        Zip archive data, encrypted compressed size: 107, uncompressed size: 81, name: README.md
1522437       0x173B05        Zip archive data, encrypted compressed size: 272, uncompressed size: 328, name: wrangler.toml
1523953       0x1740F1        End of Zip archive, footer length: 22
```

观察到图片文件命名为 `__p0.png`，我们可以联想到这张图片的原始文件名可能是 `<某个数字id>_p0.png`。通过以图搜图工具（例如 SauceNAO 或者 ASCII2D）搜索这张图片，我们可以找到原始图片的文件名为 `116921220_p0`。

所以压缩包的密码可能是 `116921220`，解压缩得到题目的源码（即本仓库的内容）。

### EdTunnel，Wrangler 和 SSRF

这部分开始就是 Web 的部分了。

观察 [docker-compose.yml](./docker/docker-compose.yml)，我们可以看到一个名为 `edtunnel` 的服务。Flag 存在于 Worker 的`env`变量中。

EdTunnel 部分是来自 <https://github.com/3Kmfi6HP/EDtunnel> 的代码，只对 UUID 和默认路由进行了简单的修改。

可以看到，EdTunnel 是通过 Wrangler 本地的开发模式部署的，查看 Wrangler 的 GitHub，可以发现 [CVE-2023-7080](https://github.com/cloudflare/workers-sdk/security/advisories/GHSA-f8mp-x433-5wpf)，这个漏洞描述了 Wrangler 的 Inspector 端口是对所有接口监听的，所以攻击者可以在临近网络上访问到 Inspector 端口从而实现 Worker 沙盒内的远程代码执行。

虽然题目版本的 Wrangler 已经修复了这个漏洞，但是由于这个代码的作用是使用 Cloudflare Worker 的 API 实现一个 VLESS over WebSocket 的代理，所以我们可以通过这个代理来 SSRF 到部署 EdTunnel 的容器，从而实现连接到 Inspector 的端口。

具体建立连接将 V8 Inspector 端口暴露到本地的配置文件可以参考 [exp-config.json](./docker/exp-config.json)，使用 `v2ray run -c exp-config.json -format jsonv5` 命令来运行。（因为 V4 版本的 V2Ray 对传输层流量多层代理支持不佳）

将端口暴露到本地后，我们可以在 Chrome 的 DevTools 中直接连接到这个端口（左上会出现 Node.js 的标识）。在 DevTools 的 Memory Snapshot 中，我们可以打出 Heap Snapshot，然后在其中搜索关键字即可找到 Flag 变量。

![图片](https://github.com/mix-archive/MessyStack/assets/32300164/511a5fd9-f10b-451f-9d71-bde059429755)

> What a messy protocol & lessy debugger!
