# Go croc relay 接入实现

2026-10-14。Cayman 默认使用 `croc.schollz.com:9009`，也支持 `--relay HOST:PORT`。仅显式指定发送端 `--listen IP:PORT` 或接收端 `--connect IP:PORT` 时走直连。不会把中继地址当成发送端地址，也不会在中继失败后自动降级。

## 实现边界

适配目标是 [croc v11.5.3 的传统 TCP 接入协议](https://github.com/schollz/croc/blob/v11.5.3/src/tcp/tcp.go)，曲线交换参照 [schollz/pake v3.2.0](https://github.com/schollz/pake/blob/v3.2.0/pake.go) 的 SIEC 模式；曲线参数固定为 [siec c2c6f6198406](https://github.com/tscholl2/siec/blob/c2c6f6198406/siec.go)，对应本机 croc v11.5.3 二进制记录的依赖版本。使用单个中继房间承载持续同步，未实现 croc 多数据端口、快速接入 capability 或 croc 文件传输协议。两端都必须使用 Cayman；复用中继不等于与 croc 客户端互传。

`src/relay/pake.rs` 仅用于中继接入：固定公开输入 `[1,2,3]`，SIEC255 参数及大整数 JSON 编码匹配上游。使用 crypto-bigint 模域计算、Jacobian 坐标、固定迭代标量乘法与条件选择；对输入点检查范围、曲线与子群。它不是用户短口令 PAKE API，未经独立安全审计。端到端身份验证由独立 SPAKE2 短码握手、双向确认及其绑定的 rustls TLS 通道承担，详见 [短码协议](short-code-pairing.md)。

## 连接过程

1. 两端分别主动连接中继。默认接入密码为 `pass123`；私有中继可通过 `--relay-password-file` 指定。
2. 按 `croc` magic + 4 字节小端长度读写接入帧，完成 SIEC PAKE。接入帧上限 64 KiB，连接和接入合计超时 30 秒。
3. 使用随机 8 字节 salt、PBKDF2-HMAC-SHA256（100 轮，与上游协议一致）派生接入密钥；AES-256-GCM 编码为 nonce + ciphertext + tag，交换接入密码、banner、房间与确认。
4. 房间标识为 `cayman-spake2-v1-` 加短码中的 6 位公开房间号。4 个秘密单词不参与房间名称计算；中继不能用路由标识离线验证单词猜测。
5. 发送端确认入房后输出邀请码。双方交换 Cayman 中继通道标记，等待期间只允许 croc 的 `[1]` 心跳帧，总等待不超过 10 分钟。中继自身的超时可以更短。
6. 收到对端标记后，先在底层字节流执行端到端 SPAKE2、密钥确认和 TLS 凭据交换，再开始 TLS。此后不再解析中继帧。精确读取长度，避免入房确认与后续数据合并到达时误吞字节。
7. 接收方固定发送方证书指纹，并通过 TLS 发送随机 256 位认证秘密。发送方确认后开始原有增量同步流程；目标路径始终由接收端配置。

中继接入密码只控制服务使用权限，不是文件加密密钥，也不能作为中继服务器的可信身份凭据。中继可拒绝服务、抢占房间或观察流量，但不能凭房间 ID 通过端到端认证。接入/配对/TLS 失败即退出，不复用半完成握手的连接。

## 已执行的验证

- `tools/relay_vectors.go` 使用 Go 标准库的独立仿射大整数实现生成固定输入向量；Rust Jacobian 实现与其比较公钥 JSON 和会话密钥。另验证 PBKDF2 与 Go AES-GCM 生成的密文。这是独立参考计算，**不是实际调用上游 Go PAKE 包的互操作测试**。
- 内存双工流验证接入成功、错误密码、房间已满、限流、错误 magic、长度超限、截断、碎片化心跳以及紧随标记的 TLS 字节不会丢失。
- 模拟中继完成双端接入并转发字节，运行实际 rustls TLS、短码 SPAKE2、TLS 认证和文件传输。
- CLI 测试验证默认中继、地址覆盖以及显式直连与中继参数互斥。

参考向量可以重新生成：

```bash
go run tools/relay_vectors.go > tests/fixtures/relay-v11.5.3.json
cargo test --offline relay::
```

## 待执行的网络验证

当前沙箱无法解析外网域名，且绑定回环 TCP 端口返回 `Operation not permitted`。因此没有把公共节点或真实 Go relay 标记为已实测兼容。

正常终端安装 croc v11.5.3 后运行：

```bash
cargo test --offline --test remote_cli actual_go_croc_relay -- --ignored --nocapture
```

该测试会启动真实 Go croc relay，运行两轮 Cayman 发送/接收并验证增量更新后的内容，以及错误接入密码被拒绝。测试结束会清理进程和临时目录。它不访问公共节点。所有 TCP 测试可通过 `cargo test --offline --test remote_cli -- --ignored` 执行。

公共节点测试请使用默认的两端命令传输小型非敏感测试目录；公共服务的版本、配额和可用性不由 Cayman 控制。未通过真实中继验证前，应将本适配视为实验性实现。
