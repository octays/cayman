# Cayman

Rust 跨机器增量同步工具，开发中。默认通过 Go croc 中继连接，使用 SPAKE2 短码配对和端到端 TLS。发送端只选择源文件或目录，接收端决定目标目录；不提供 local-sync。

命令支持短别名：`s` 等同于 `send`，`r` 等同于 `receive`。例如 `cayman s ./docs`、`cayman r .`。

## 安装最新 Release

支持 Linux / macOS 的 amd64 和 arm64。Linux 使用静态 musl 二进制，也适用于 Alpine 和 WSL；其他系统或架构会明确报错。

**Linux 和 macOS 默认安装路径均为 `/usr/local/bin/cayman`。** 普通用户在目录不可写时会收到 sudo 密码提示；root 用户直接安装，无需 sudo。

安装或更新到最新正式版：

```bash
curl -fsSL https://raw.githubusercontent.com/octays/cayman/master/scripts/install.sh | bash
```

安装后验证：

```bash
/usr/local/bin/cayman --version
```

也可以先下载脚本再执行：

```bash
curl -fsSL https://raw.githubusercontent.com/octays/cayman/master/scripts/install.sh -o install-cayman.sh
bash install-cayman.sh
```

如需无需管理员权限的用户级安装，可自定义目录：

```bash
curl -fsSL https://raw.githubusercontent.com/octays/cayman/master/scripts/install.sh | CAYMAN_INSTALL_DIR="$HOME/.local/bin" bash
```

脚本自动识别系统和架构，从 `octays/cayman` 的最新正式 Release 下载对应二进制，校验 SHA-256，验证程序可运行后原子替换。下载或校验失败会保留已有安装。依赖 Bash 3.2+、curl 和 sha256sum 或 shasum。不修改 shell 配置，必要时会提示添加 PATH。仓库需先发布至少一个正式 Release。

## 构建与发布

[Release 工作流](.github/workflows/release.yml) 在推送 `v*` 标签时构建四种独立二进制文件：

- `cayman-linux-amd64`
- `cayman-linux-arm64`
- `cayman-darwin-amd64`
- `cayman-darwin-arm64`

每个二进制附带 `.sha256` 文件。Linux 必须通过 UPX 压缩、完整性检测和运行检查；macOS 尝试 UPX，格式不支持或运行检查失败时保留原二进制。构建日志记录最终压缩方式；依赖的许可证和来源说明作为独立附件保留。所有平台构建成功后创建并发布 GitHub Release；带连字符的版本标签（如 `v0.2.0-rc.1`）标记为预发布，安装脚本不会选择它。手动运行工作流可下载构建产物，只有标签运行会发布 Release。

发布前更新 `Cargo.toml` 的版本并更新锁文件，然后提交并推送标签，例如：

```bash
git tag v0.1.0
git push origin v0.1.0
```

工作流使用 GitHub 托管的原生架构 runner，参考 [GitHub runner 文档](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)；压缩工具参考 [UPX 官方文档](https://github.com/upx/upx/blob/devel/doc/upx-doc.txt)。当前不提供 Windows 原生二进制，因为接收端尚未支持 Windows。

## 默认通过中继同步

发送端：

```bash
cargo run -- send ./docs
```

发送单个文件：

```bash
cayman send upgrade-go.sh
# 接收端保存为 ./received/upgrade-go.sh
cayman receive ./received
```

单文件同样支持 `--watch` 持续增量更新，只共享指定文件，不扫描或发送同目录的其他文件。文件源不能带末尾 `/`；符号链接与特殊文件不支持。接收端参数始终是目标目录，文件使用原文件名。当前不保留执行权限等元数据，脚本接收后可通过 `bash upgrade-go.sh` 执行。

源路径末尾决定接收端的目录布局（假设接收端运行 `cayman receive ./received`）：

| 发送命令 | 接收位置 |
| --- | --- |
| `cayman send docs` | `received/docs/`，包含 docs 目录本身 |
| `cayman send docs/` | `received/`，仅放入 docs 内的内容 |
| `cayman send docs/.` | 同 `docs/` |
| `cayman send .` | 将当前目录的内容放入 `received/` |

空目录也会同步；中继和直连模式规则一致。旧版本始终发送目录内容，升级后若需保持原布局，请给源目录加 `/`。`sync` 子命令已移除，使用 `cargo run -- send docs`。

发送端会显示类似 `Pairing code: 482731-maple-river-otter-cloud` 的短码。

接收端：

```bash
cargo run -- receive ./received-docs
# 按提示粘贴发送端显示的完整配对码
```

两端默认连接 `croc.schollz.com:9009`，使用其默认接入密码 `pass123`。双方都只发起出站 TCP 连接，无需配置发送端公网 IP 或监听端口。公共节点在当前环境尚未实测，服务可用性取决于该节点及本地网络。

使用其他现有 Go croc relay 时，两端指定同一个地址：

```bash
cargo run -- send ./docs --relay relay.example.com:9009
cargo run -- receive ./received-docs --relay relay.example.com:9009
```

私有中继密码通过 `--relay-password-file /path/to/password` 读取；它与端到端配对码相互独立。无需另写 Cayman relay 服务端。Rust 接入层按 [croc v11.5.3](https://github.com/schollz/croc/tree/v11.5.3) 的传统接入协议实现，不要求用户安装 Go 或 croc 客户端。实际 Go 中继互操作测试仍待在允许联网和监听端口的环境运行，详见 [适配说明](docs/relay-implementation.md)。

默认只传输一轮，完成后发送端与接收端均退出。单轮传输也会比对和复用已有文件块。无需 `--state-dir`；接收端自动在目标目录内维护 `.cayman` 状态。

```bash
cayman send ./docs
cayman receive ./received
```

发送端添加 `--watch` 开启持续增量同步，每秒检查目录元数据，发现变化后执行增量同步：

```bash
cayman send ./docs --watch
cayman receive ./received
```

接收端无需额外参数，自动跟随发送端的模式。首次同步与后续变化显示单行进度，完成后保留汇总；无变化轮询保持安静。持续模式可用 Ctrl+C 停止。旧的 `--once` 参数已移除。

## 显式选择直连

只有提供以下参数才使用直连，不会在中继失败后自动切换：

```bash
# 发送端
cargo run -- send ./docs --listen 0.0.0.0:9009
# 接收端：换成可达的发送端 IP
cargo run -- receive ./received-docs --connect 192.168.1.10:9009
```

`--listen` / `--connect` 与中继配置互斥。直连需要发送端 TCP 端口可达。

## 配对与加密

通过可信渠道交给接收方完整短码，也可使用发送端 `--code-file /path/outside/source/invite` 写入新文件，再由接收端 `--code-file /path/to/invite` 读取。不会覆盖已有邀请码文件，Unix 下以 0600 权限创建；请勿放入共享目录。

短码由 **6 位公开房间号 + 4 个随机单词**组成。每个单词从固定的 256 词词表均匀选择，秘密部分共 32 位随机熵；房间号不计入秘密熵。中继只收到房间号派生的路由名称，不收到单词或整个短码的哈希。

双方执行 SPAKE2 并双向确认密钥，绑定协议版本、房间号和发送/接收角色。确认成功后，通过认证加密交换本次 TLS 的证书指纹与随机认证秘密，再建立固定证书的 TLS 1.3 通道。文件内容和元数据仍通过 TLS 传输；未完成认证不会访问接收目录。具体流程见 [短码配对协议](docs/short-code-pairing.md)。

每次启动生成新码，最多等待另一端 10 分钟（中继可能更早清理房间），配对握手限时 30 秒。一次启动只允许一次配对尝试；错误短码或连接中断会结束本次会话，重新运行发送端获取新码。短码不支持自选弱密码。接收时允许单词大小写和整行首尾空白。

**两端都需要升级。** 原先 `cayman-direct-v1:...` 长码不再作为用户输入；旧实例需重启生成短码。短码与 croc 体验类似，但两端仍须运行 Cayman，不能与官方 croc 客户端互传。自动重连和直连 NAT 穿透尚未实现。

## 增量与可靠性

- 按 256 KiB 固定块进行 SHA-256 比对，只请求缺失块；复用同名目标文件中的相同块，完成后再次验证整个文件。
- 临时文件写入、同步后原子替换，保存提交意图与共同基线。进程重启会检查待完成提交；已完成文件可跳过，未完成文件需要重新比对。
- 首次遇到已有且内容不同的文件默认报告冲突。接收端显式指定 `--replace-existing` 才允许接管此类文件；有共同基线后，接收端自行修改或删除的文件仍受到冲突保护。
- 覆盖已有文件前，在 `.cayman` 内保留旧内容与备份信息。单轮遇到冲突返回失败；持续模式保留冲突文件并继续下一轮。
- 接收目录独占锁、路径校验、符号链接拒绝、帧长度上限与超时。`.cayman` 是保留目录，不能作为业务文件名。

同步汇总将文件结果与数据量分开，例如：

```text
Files: 1 updated, 4 unchanged | Conflicts: 0
File data: 27875 bytes transferred, 0 bytes reused locally
```

`updated` 包含新增或替换且已成功提交的文件，`unchanged` 表示内容相同的文件；目录不计入这两个文件计数，冲突计数可能包含目录。数据量统计已成功提交文件的原始内容字节，不是网卡流量，不包含元数据、JSON 编码、TLS 开销或未提交传输。`reused locally` 只统计更新文件时复用的本地块，不包含整个跳过的未变化文件。

比对发生在发送文件内容之前：发送端在本地读取源文件，先发送路径、大小和整文件 SHA-256，只有接收端需要更新时再发送每个 256 KiB 块的 SHA-256；接收端在本地计算已有文件摘要，相同则跳过，不同且允许更新时请求缺失块。本地匹配块可在同一个目标文件的其他块位置复用。接收端重建临时文件，校验整文件后原子提交。

摘要采用有容量上限的会话内缓存，以大小、修改时间以及 Unix 设备号、inode、ctime 判断是否可复用。`--watch` 每秒轮询目录元数据；源端无变化时只交换心跳，不重复发送文件清单或读取内容。每 60 秒清空两端缓存并执行完整校验，补偿元数据检测遗漏并检查接收端变化。源端变化时仍发送一轮完整的轻量文件摘要，批量清单和原生文件系统事件监听尚未实现。首次遇到相同文件无需传输块摘要或文件内容。缓存不跨进程持久化；最终提交前仍重新读取并核对目标，避免缓存削弱本地修改冲突保护。

摘要目前仍使用 JSON 编码并逐文件交互。小于 256 KiB 的文件只有一个块，改动一个字节也要重传整个文件内容；大文件中部插入数据可能使后续固定块边界错位。此次文件同步握手已升级为 `cayman-sync/2`，两端需同时更新，旧版本会拒绝连接。

当前实现是目录元数据轮询的单向同步：不传播删除，不保留权限、时间戳等元数据，不实现双向合并、原生文件事件监控或持久化块级断点续传。新文件使用临时文件的私有权限。目标目录应由可信本机用户管理；当前路径检查不能防御恶意本机进程并发替换目录。

接收端目前支持 Unix（macOS/Linux）。原型限制：每轮最多 10,000 个条目、单文件最多 1 GiB，接收端 `--max-bytes` 默认为每轮声明文件总大小 10 GiB。这不是累计磁盘配额；历史备份尚无自动清理策略。JSON 数据帧存在编码开销，尚未实现二进制块编码、CDC、压缩、索引缓存和并行传输。源文件在传输中变化时可能终止本次会话；断线后需重启发送端并使用新码连接。

## 验证

```bash
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
# vendored SPAKE2 的上游向量及文档测试：
cargo test --offline --manifest-path vendor/spake2/Cargo.toml --features std
# 在允许监听回环 TCP 端口的终端另行运行：
cargo test --offline --test remote_cli -- --ignored
```

默认测试包含短码生成/解析、SPAKE2 错码和房间绑定、握手篡改拒绝、Go 独立算术参考向量、模拟中继接入/心跳/拒绝响应，以及内存双工流上的真实 TLS 握手、证书固定、秘密认证、远程传输、持续增量更新、冲突保护与状态恢复。三个真实 TCP 测试需要显式运行，其中 Go 中继测试需 PATH 中有 croc v11.5.3；当前开发沙箱禁止监听端口，尚未在此环境通过这些测试。内存测试不能替代跨机器实测。

`--offline` 需要依赖缓存；首次联网构建可去掉它。SPAKE2 0.4.0 源码已随项目纳入，来源及适配记录见 [VENDOR.md](vendor/spake2/VENDOR.md)。HKDF/HMAC/AES-GCM 记录模块现在用于 SPAKE2 密钥确认和 TLS 凭据的认证加密；文件数据通道仍使用 rustls TLS。

后续路线与设计：[基础实施方案](docs/implementation-plan.md)、[性能与同步](docs/performance-reliability-sync.md)、[p2sync 评估](docs/p2sync-review.md)。

终端进度每秒最多刷新 10 次：总体百分比按本轮已处理条目数计算（含目录和未变化文件），当前文件百分比按需传输的字节数计算，不包含复用块。首次同步显示 Initial sync，后续变化显示 Incremental sync；无变化轮询保持安静。输出重定向时仅保留汇总，不写入进度控制字符。
