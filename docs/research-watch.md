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
- 超过每日数量上限的结果进入后续队列。已接受的报告持续检查修订；报告正文或目标源码指纹变化后重新分析。相同内容不重复调用模型。
- 只抓取公网 HTTPS 文本页面；解析并固定连接地址，重定向逐跳重新检查。不执行网页脚本，不下载或运行逆向工具。
- 报告必须经模型判断为相关原创技术分析；文章中的机制、触发条件、日期与版本要引用原文连续片段。确定性检查会核对引用存在，第二次模型复核同时读取原文与源码。此流程提供证据审查，不能保证模型判断永远正确。
- 代码只读取目标 Git 提交中明确配置目录下的普通源码文件，支持 `.mjs`、`.cjs`；不读取本机未提交文件、凭证或链接文件。默认每次最多选择 12 个文件、48KB 代码；超出范围或上下文不完整时不得给出确定过滤结论。

## 首页四项信息

| 信息 | 规则 |
| --- | --- |
| 隐写机制 | 描述机制，附原始报告链接及报告分析版本 |
| 过滤状态 | 已过滤／未过滤／部分过滤／待核实；附代码路径、行号、审阅提交与理由 |
| 触发条件 | 依据报告描述，不能把新版环境自行代入旧版结论 |
| 发现／引入时间 | 完全依报告口径；未说明则明确标注，不用检索日期补齐 |

“未过滤”需要实际保留或透传代码证据，“已过滤”需要实际去除路径，单纯找不到过滤函数不能构成判断。过滤结果属于静态分析，不代表已经用真实 CLI 流量验证。复核不支持时降级为待核实。

程序只替换 README 中 `<!-- termiters:research:start -->` 与 `<!-- termiters:research:end -->` 之间的区域；首次运行追加该区域。原有首页正文保持不变。不同报告分别保留来源与版本；来源修订后不再支持旧记录时标为待核实，不继续冒充最新证据。

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
