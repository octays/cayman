# Cayman

Rust 跨机器增量同步工具，开发中。默认通过 Go croc 中继连接，使用 SPAKE2 短码配对和端到端 TLS。发送端只选择源文件或目录，接收端决定目标目录；不提供 local-sync。

命令支持短别名：`s` 等同于 `send`，`r` 等同于 `receive`。例如 `cayman s ./docs`、`cayman r .`。

## 安装最新 Release

安装脚本支持 Linux / macOS 的 amd64 和 arm64。Windows amd64 可从 Release 下载 `cayman-windows-amd64.exe`，改名为 `cayman.exe` 后放入 PATH。Linux 使用静态 musl 二进制，也适用于 Alpine 和 WSL；其他系统或架构会明确报错。

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

[Release 工作流](.github/workflows/release.yml) 在推送 `v*` 标签时构建五种独立二进制文件：

- `cayman-linux-amd64`
- `cayman-linux-arm64`
- `cayman-darwin-amd64`
- `cayman-darwin-arm64`
- `cayman-windows-amd64.exe`

每个二进制附带 `.sha256` 文件。Linux 和 Windows 必须通过 UPX 压缩、完整性检测和运行检查；macOS 尝试 UPX，格式不支持或运行检查失败时保留原二进制。构建日志记录最终压缩方式；依赖的许可证和来源说明作为独立附件保留。所有平台构建成功后创建并发布 GitHub Release；带连字符的版本标签（如 `v0.2.0-rc.1`）标记为预发布，安装脚本不会选择它。手动运行工作流可下载构建产物，只有标签运行会发布 Release。

发布前更新 `Cargo.toml` 的版本并更新锁文件，然后提交并推送标签，例如：

```bash
git tag v0.3.0
git push origin v0.3.0
```

工作流使用 GitHub 托管的原生架构 runner，参考 [GitHub runner 文档](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)；压缩工具参考 [UPX 官方文档](https://github.com/upx/upx/blob/devel/doc/upx-doc.txt)。Windows 构建会在原生 runner 上运行 Rust 测试；Bash 安装脚本只支持 Linux/macOS。

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

发送端添加 `--watch` 开启持续增量同步，通过原生文件事件发现变化，并每 60 秒完整校验兜底：

```bash
cayman send ./docs --watch
cayman receive ./received
```

接收端无需额外参数，自动跟随发送端的模式。首次同步与后续变化显示单行进度，完成后保留汇总；无变化轮询保持安静。持续模式可用 Ctrl+C 停止。旧的 `--once` 参数已移除。

## 双向同步和删除传播

默认单向、不删除。目录双向同步需要双方显式同意；不支持单文件双向同步：

```bash
cayman send ./docs --watch --bidirectional
cayman receive ./received --bidirectional
```

此时 `docs/` 与 `received/docs/` 双向交换新增和修改。只有一端修改时传播到另一端；双方修改同一文件时保留双方内容并报告冲突，不自动选择胜者或合并文本。去掉发送端 `--watch` 则只协调一轮后退出。

需要同步删除时，两端都添加 `--delete`：

```bash
cayman send ./docs --watch --bidirectional --delete
cayman receive ./received --bidirectional --delete
```

单向同步也可使用双方 `--delete`。只删除本同步范围内曾确认同步、且未被本地修改的文件；删除前备份，未知文件保留，只清理已跟踪的空目录。删除与另一端修改冲突时保留修改。这不是对目标目录执行无条件镜像删除。双向模式会在源目录和目标目录都创建 `.cayman`，删除和双向同步的状态绑定同步范围，不能随意改用于另一对目录；普通单向传输可共用目标目录，切换来源会清空删除归属，不继承其他来源的删除权限。

`--watch` 在已认证会话中遇到网络中断时自动重连。重连使用内存中的高熵凭据和新 TLS 连接，不重新尝试短码 PAKE；退避从 1 秒增长至 30 秒，每个进程最多重试 10 次。两端进程需要保持运行，重启任一端后需重新配对。已提交文件会重新比对并跳过；未完成文件重新传输缺失块，尚无持久化的分块进度恢复。认证、协议、文件系统错误不会作为普通断线无限重试。

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

每次启动生成新码，最多等待另一端 10 分钟（中继可能更早清理房间），配对握手限时 30 秒。一次启动只允许一次配对尝试；错误短码或配对阶段中断会结束本次配对，重新运行发送端获取新码；成功认证后的持续会话支持自动重连。短码不支持自选弱密码。接收时允许单词大小写和整行首尾空白。

**两端都需要升级。** 原先 `cayman-direct-v1:...` 长码不再作为用户输入；旧实例需重启生成短码。短码与 croc 体验类似，但两端仍须运行 Cayman，不能与官方 croc 客户端互传。直连 NAT 穿透尚未实现。短码、PAKE、端到端加密是 Cayman 与 croc 共有的能力；Rust 本身不意味着协议更安全，项目尚未经过独立安全审计，详见 [安全边界](SECURITY.md)。

## 增量与可靠性

- 使用 FastCDC 内容定义分块（最小 64 KiB、目标平均 256 KiB、最大 1 MiB）进行 SHA-256 比对，只请求缺失块；复用同名目标文件中的相同块，完成后再次验证整个文件。
- 临时文件写入、同步后原子替换，保存提交意图与共同基线。进程重启会检查待完成提交；已完成文件可跳过，未完成文件需要重新比对。
- 首次遇到已有且内容不同的文件默认报告冲突。接收端显式指定 `--replace-existing` 才允许接管此类文件；有共同基线后，接收端自行修改或删除的文件仍受到冲突保护。
- 覆盖已有文件前，在 `.cayman` 内保留旧内容与备份信息。单轮遇到冲突返回失败；持续模式保留冲突文件并继续下一轮。
- 接收目录独占锁、路径校验、符号链接拒绝、帧长度上限与超时。`.cayman` 是保留目录，不能作为业务文件名。

同步汇总将文件结果与数据量分开，例如：

```text
Files: 1 updated, 4 unchanged, 0 deleted | Conflicts: 0
File data: 27875 bytes transferred, 0 bytes reused locally
```

`updated` 包含新增或替换且已成功提交的文件，`unchanged` 表示内容相同的文件；`deleted` 表示本轮删除的文件；目录不计入文件计数，冲突计数可能包含目录。数据量统计已成功提交文件的原始内容字节，不是网卡流量，不包含元数据、控制消息、帧头、TLS 开销或未提交传输。`reused locally` 只统计更新文件时复用的本地块，不包含整个跳过的未变化文件。

比对发生在发送文件内容之前：发送端在本地读取源文件，先发送路径、大小和整文件 SHA-256，只有接收端需要更新时再发送 CDC 块的长度和 SHA-256；接收端在本地计算已有文件摘要，相同则跳过，不同且允许更新时请求缺失块。双方使用相同的 FastCDC 参数独立分块，按 `(SHA-256, 长度)` 匹配，本地块可在同一个目标文件的其他偏移处复用。接收端重建临时文件，校验整文件后原子提交。

摘要采用有容量上限的会话内缓存，以大小、修改时间以及 Unix 设备号、inode、ctime 判断是否可复用。原生监听使用 Linux inotify、macOS kqueue、Windows 目录变更通知；每秒处理变化提示，无事件时只交换心跳。每 60 秒清空两端缓存并完整校验，补偿事件遗漏和元数据未变化的内容修改。监听资源不足时退回每秒元数据轮询；macOS 监听需要为文件持有描述符，大目录可能触发此回退。变化后仍交换完整的文件摘要清单，没有目录 Merkle 索引。

块摘要和缺失块请求以最多 1,024 项分页，避免单个大文件的块清单超出帧上限。传输控制帧以 `0` 类型字节开头，后接 JSON；数据帧以 `1` 开头，后接 8 字节大端块编号和原始块内容。外层仍是有界长度前缀，数据受 TLS 保护；最大数据载荷为 1 MiB + 9 字节。

CDC 使用锁定的 `fastcdc = 5.0.0`、`v2020::StreamCDC`、Normalization Level1、seed 0。完整配置标识在加密会话内校验；参数没有协商降级，也不随文件大小动态变化。分块依据内容，在插入或删除后通常能重新找到相同边界，减少后续内容重传；不能保证每次只重传一个块，更不等于逐字节增量。小于 64 KiB 的文件仍作为一个块，重新压缩或加密的文件也可能无法有效复用。

FastCDC 的 Gear 哈希只用于找边界，块身份和整文件完整性继续使用 SHA-256。每个变化文件仍需本地扫描，CDC 节省的是网络流量，不保证减少磁盘读取。流式分块不把整文件装入内存；清单与复用索引仍保存在内存，每个文件最多 1,048,576 块，超过会明确报错。每页还校验顺序、块长度、累计字节数，目标偏移只能由长度累加产生，不能由发送端指定任意写入位置。

目前只复用同名旧文件中的块，没有跨文件去重、磁盘块索引、压缩或并行传输。文件清单仍逐条交互，没有充分的跨机器性能基准来宣称比 croc 更快。

接收端实现支持 Linux、macOS 和 Windows。Windows 拒绝重解析点（包括 junction），使用文件锁及临时文件替换，但没有 Unix 目录 fsync 的同等掉电持久性保证；占用文件、杀毒软件或权限限制可能令替换失败。不会保留权限、时间戳、ACL 等元数据，不支持符号链接和特殊文件；目标目录必须由可信本机用户管理，路径检查不能防御恶意本机进程并发替换目录。

默认资源上限已从单文件 1 GiB / 每轮 10,000 条提升为：

| 参数 | 默认 / 上限 | 含义 |
| --- | --- | --- |
| `--max-file-bytes` | 256 GiB，大小上限 | 单文件字节数，可调低；另受块数上限约束 |
| `--max-files` | 100,000，协议上限 | 每轮文件与目录条目总数，可调低 |
| `--max-bytes` | 1 TiB，可配置 | 每轮声明文件大小之和 |

两端均可设置限制，双向时分别约束本地发送和接收。分页限制了单帧大小，但文件摘要和索引仍占用内存，状态文件会整体重写。CDC 每文件还有 1,048,576 块上限：超过 64 GiB 的文件可能因实际分块数量而提前达到上限，256 GiB 不是任意内容都可传输的保证。十万级目录和 256 GiB 文件并未做完整规模压测。配额不是累计磁盘限制；历史备份尚无自动清理。源文件在传输期间变化可能使本次会话失败，使用稳定文件或文件系统快照更合适。

v0.3 使用 `cayman-session/4` 会话协议（内部传输协议也升级为 v4），双方必须同时升级；旧版本会拒绝连接。v0.2 的整文件基线和备份可继续使用，块清单缓存会重新计算，不要求删除 `.cayman`。状态格式从 1 迁移为 2；升级后不要用旧程序打开新状态目录。旧状态首次绑定范围时只把重新验证过的文件纳入可删除集合，旧布局下的 `.cayman` 不会自动跨目录搬迁。不要删除 `.cayman` 来解决冲突，否则会丢失共同基线和历史。

## 验证

```bash
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
# vendored SPAKE2 的上游向量及文档测试：
cargo test --offline --manifest-path vendor/spake2/Cargo.toml --features std
# 在允许监听回环 TCP 端口的终端另行运行：
cargo test --offline --lib watch_reconnects_after_transport_is_cut -- --ignored
cargo test --offline --test remote_cli -- --ignored
```

CDC 测试覆盖流式与上游切片分块的一致性、短读取与 EINTR、插入/删除/覆盖/追加的块复用，以及实际内存传输与固定块的传输量对照。默认测试还覆盖双向单边修改与冲突、删除授权和备份、原生文件事件、重连凭据认证、超过 1 GiB 文件的分页握手（不是完整大文件传输压测）。默认测试包含短码生成/解析、SPAKE2 错码和房间绑定、握手篡改拒绝、Go 独立算术参考向量、模拟中继接入/心跳/拒绝响应，以及内存双工流上的真实 TLS 握手、证书固定、秘密认证、远程传输、持续增量更新、冲突保护与状态恢复。另外三个进程级真实 TCP 测试需要显式运行，其中 Go 中继测试需 PATH 中有 croc v11.5.3；当前开发沙箱禁止监听端口，尚未在此环境通过这些测试。内存测试不能替代跨机器实测。

`--offline` 需要依赖缓存；首次联网构建可去掉它。SPAKE2 0.4.0 源码已随项目纳入，来源及适配记录见 [VENDOR.md](vendor/spake2/VENDOR.md)。HKDF/HMAC/AES-GCM 记录模块现在用于 SPAKE2 密钥确认和 TLS 凭据的认证加密；文件数据通道仍使用 rustls TLS。

以下为早期设计资料，当前已实现功能和限制以本 README 为准：[基础实施方案](docs/implementation-plan.md)、[性能与同步](docs/performance-reliability-sync.md)、[p2sync 评估](docs/p2sync-review.md)。

终端进度每秒最多刷新 10 次：总体百分比按本轮已处理条目数计算（含目录和未变化文件），当前文件百分比按需传输的字节数计算，不包含复用块。首次同步显示 Initial sync，后续变化显示 Incremental sync；无变化轮询保持安静。输出重定向时仅保留汇总，不写入进度控制字符。
