# 每日逆向报告研究

一次启动完成“关键词检索 → DeepSeek 核验报告 → 对照代码 → 独立复核 → 更新首页”，随后退出。系统定时任务负责次日重新启动。旧命令保持兼容，研究功能单独配置。

## 单次运行

复制 `examples/research.json`、`examples/research-llm.yml` 到本机私有配置目录，设置目标仓库、提交身份与 `enabled: true`，通过环境变量提供模型凭证。配置不包含实际密钥。示例默认禁止发布，启用 `publish: true` 后自动提交和普通快进推送 README。

```sh
TermiteRS research run-once --config /etc/termiters/research.json --preview
TermiteRS research run-once --config /etc/termiters/research.json
```

需要 Git、Python 3.10+ 和目标仓库的推送凭据。Windows 可以用 `--python C:/path/to/python.exe` 指定解释器。模型使用现有 TermiteRS HTTP 传输、重试与超时逻辑；模型输出不能执行 shell 命令。

`state_dir` 和 `llm_config` 相对研究 JSON 所在目录解析。服务器建议将 `state_dir` 设置为 `/var/lib/termiters/research`。各轮状态在 `state.sqlite3`，最近执行结果在 `last-run.json`，待发布首页在 `README.preview.md`。预览不会推送，也不会更新用户工作区。

## 检索与证据

- 示例使用 Google 网页检索，不需要搜索密钥；遇到必须执行 JavaScript 的页面，可安装 Playwright 和 Chromium，在 `search.browser_enabled` 中启用正常浏览器渲染，并通过 `--python` 指定安装该依赖的 Python。验证码不会自动处理，搜索失败会明确报错，不视为“没有新报告”。原有 `bing_rss` 和 `brave` 提供方仍可选，后者读取环境变量 `BRAVE_SEARCH_API_KEY`。
- 每日继续搜索，不以“今天是否升级”作为唯一条件，因此晚发布、晚索引的报告仍能被发现。`seed_urls` 用于补充已知原始报告。
- `required_keywords` 对搜索结果的标题、摘要及 URL 做任一关键词匹配，空列表关闭预筛选；报告真实性仍交给模型核验。已知原始来源优先进入待处理队列。
- `search.enabled: false` 可暂时关闭检索，只验证 `seed_urls` 中的原始报告。模型的结构化阶段结果缓存在私有状态目录，调试校验时复用；原文、代码、模型配置变化后重新请求。错误记录保留校验原因，便于定位未发布的报告。
- 超过每日数量上限的结果进入后续队列。已接受的报告持续检查修订；报告正文或目标源码指纹变化后重新分析。相同内容不重复调用模型。
- 只抓取公网 HTTPS 文本页面；解析并固定连接地址，重定向逐跳重新检查。不执行网页脚本，不下载或运行逆向工具。
- 报告必须经模型判断为相关原创技术分析；文章中的机制、触发条件与版本要引用原文连续片段。确定性检查会核对引用存在，第二次模型复核同时读取原文与源码。此流程提供证据审查，不能保证模型判断永远正确。
- 代码只读取目标 Git 提交中明确配置目录下的普通源码文件，支持 `.mjs`、`.cjs`；不读取本机未提交文件、凭证或链接文件。模型最多选择 12 个文件，配置可指定最多8个 `required_code_paths` 优先读取，合计不超过20个。默认 `max_code_bytes` 为96000，关键实现优先于测试；超出范围或上下文不完整时不得给出确定过滤结论。
- 过滤判断针对适配器已展示的处理路径，不把它与“当前官方 CLI 是否仍生成旧版标记”混为一谈。来源未公开首发日期时，发现时间记录为“未说明”，不拒绝整篇报告。
- 原文或代码引用校验失败时，执行器把具体原因退回模型纠正一次；仍不通过则停止该报告。执行器不会自行修补引用或更改研究结论。
- “发现时间”是本追踪的记账口径，直接取原报告的文章首发日期，不声称是真实首次发现或机制引入时间。执行器读取明确的首发元数据、文章标题前独立日期或 Issue 结构化首发时间；忽略修订时间、评论时间、正文研究日期与抓取日期。元数据矛盾或来源未公开日期时显示未说明，绝不用正文示例日期凑数。单纯更新首发元数据不会重跑已核验的机制与代码分析。
- 如果独立复核否定了机制、版本或触发条件，则最多退回机制提取阶段一次，再完整进行代码评估与复核，而不是反复要求复核改口。再次失败仍保留待处理，不强行发布。

## 首页四项信息

首页按报告分析版本数值从新到旧排序（范围取最高版本，版本未说明置后），以简表展示短名、过滤状态、触发摘要与发现时间，不再列引入时间。完整机制、共同前置条件、判断理由及固定提交的代码链接折叠保留，不因压缩而丢弃证据。类别区分隐写、环境标记、协议指纹和模型水印，显式协议标记不冒充隐形字符。简表摘要随原始声明一并独立复核；报告或源码变化后重新分析。末尾附 TermiteRS 在线追踪署名；署名不代表定时任务已启用，仍以部署状态为准。

| 信息 | 规则 |
| --- | --- |
| 隐写机制 | 描述机制，附原始报告链接及报告分析版本 |
| 过滤状态 | 已过滤／未过滤／部分过滤／待核实；附代码路径、行号、审阅提交与理由 |
| 触发条件 | 依据报告描述，不能把新版环境自行代入旧版结论 |
| 发现时间 | 以原报告首发日期为准；未公开则未说明，不推断引入时间 |

“未过滤”需要实际保留或透传代码证据，“已过滤”需要实际去除路径，单纯找不到过滤函数不能构成判断。过滤结果属于静态分析，不代表已经用真实 CLI 流量验证。复核不支持时降级为待核实。

程序只替换 README 中 `<!-- termiters:research:start -->` 与 `<!-- termiters:research:end -->` 之间的区域；首次运行追加该区域。原有首页正文保持不变。不同报告分别保留来源与版本；来源修订后不再支持旧记录时标为待核实，不继续冒充最新证据。

可以自由修改研究区以外的部署说明，程序每轮先获取远端最新 README，只替换这两个标记之间的生成内容，不会用历史整份 README 覆盖你的编辑。请保留两个标记；标记内的手写修改会在下一轮重新生成，手写说明应放在标记外。仅改 README 不触发源码重分析；并发提交会让推送失败，下轮重新基于最新版本生成，不强推。若重命名 README，需同步修改 `target.homepage`。

发布在状态目录内的独立裸仓库完成，不动用户 checkout。commit 格式为 `x.y.z 更新隐写记录`，版本默认读取目标 `package.json`，其他项目通过 `commit_version` 指定。遇到远端并发提交时推送失败，下轮重新读取最新代码再生成，禁止强推。只有首页实际变化时才创建提交。

## Linux 每日运行

`deploy/termiters-research.service` 与 `.timer` 是待安装模板。配置运行用户 `termiters`、模型环境文件 `/etc/termiters/research.env`、Git 推送凭据和 `/var/lib/termiters` 写权限后，将模板安装到 `/etc/systemd/system/`。模型密钥只放环境文件，权限设为 `0600`。

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now termiters-research.timer
systemctl list-timers termiters-research.timer
journalctl -u termiters-research.service
```

默认每天 03:00 UTC 后随机延迟最多 15 分钟。停机错过的轮次在恢复后补跑一次。每轮最多 2 小时，进程退出后释放锁；同一状态目录的重叠运行会失败退出。关键词、每日数量、联网与模型超时、是否发布均可配置。失败写入执行记录并让 systemd 显示失败；下一天继续重试。

## 验证

```sh
python3 -m unittest discover -s tests -p test_research_watch.py -v
cargo test --test research_cli
```

测试使用本机模拟模型与临时 Git remote，覆盖证据伪造、重复轮次、报告修订、代码更新、发布并发及未提交工作保护，不调用真实模型。

## Google 人工验证与手机接手

`TermiteRS research verify-google --config /etc/termiters/research.json --python /path/to/python` 只打开断点中的一个关键词，不调用模型、抓取报告或发布首页。需要安装 Playwright 完整 Chromium、TigerVNC 和 noVNC/websockify；原来的 headless shell 不支持显示验证窗口。

在 `search` 中设置 `browser_enabled: true`、`browser_persistent: true`、`browser_headless: false`、`verification_wait_seconds: 1200`。浏览器配置固定保存在 `state_dir/google-profile`，自动与人工入口通过独立 SQLite 事务锁互斥。每个关键词复用同一浏览器；完整搜索结束后下一轮重新检索。验证码中断前的成功结果和未完成关键词保存在 `google-search-progress.json`，恢复不重复已完成查询。修改搜索配置会使旧断点失效。

部署 `deploy/termiters-research-display.service`、`-novnc.service`、`-verify.service`，把 `termiters-research-browser.conf` 安装为研究服务的 drop-in。根据实际环境替换用户、二进制、配置、状态目录、Python 和 Playwright 浏览器路径。显示服务的 `PrivateTmp` 命名空间由研究和人工服务共享；显示和网页服务随依赖任务结束停止。不需要新增定时任务。

手机访问需要已有 HTTPS 域名。设置 `search.verification_public_url: https://your-domain.example/termite-google/` 和 `search.notification_config: /etc/termiters/termite.yml`，研究服务环境文件提供原邮件通道所需的环境变量。验证码出现后生成随机访问令牌，通过现有 TermiteRS 通知通道发送限时链接。默认20分钟内有效，完成验证、等待超时或浏览器正常关闭时撤销。邮件被提交到 SMTP 不代表收件箱已收到；应由收件人确认。手机打开链接即可查看和操作服务器浏览器，支持缩放。无需导出 Cookie 或登录 Google 账号。浏览器子进程只继承白名单环境，不继承邮件和模型密钥。

HTTPS 入口的 Nginx location 示例（加入已有 HTTPS 站点；若 TLS 由已有 CDN 终止，加入对应回源站点）：

```nginx
location ^~ /termite-google/ {
    access_log off;
    add_header Referrer-Policy no-referrer always;
    add_header Cache-Control no-store always;
    proxy_pass http://127.0.0.1:6080/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_buffering off;
    proxy_read_timeout 1300s;
}
```

VNC 与 websockify 仅监听回环地址；WebSocket 通过 `TokenFile` 校验令牌，静态 noVNC 文件不含访问凭据。接手链接不得转发，反向代理关闭该入口的访问日志，避免记录令牌。若进程被强制终止来不及清理令牌，依赖服务结束会关闭会话；每次服务启动应清空遗留令牌。

也可用 SSH 转发 `127.0.0.1:16080:127.0.0.1:6080`，把邮件链接的主机改成本地入口并移除反代路径前缀。页面验证完成后，程序只接受原关键词的 Google 搜索结果；验证码页、首页或其他查询不会冒充成功。人工操作期间程序不点击、不刷新、不跳转；超时保留断点并退出，不自动解决验证码。
