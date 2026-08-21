# TermiteRS

TermiteRS 是一个面向长期自定义分支和实际运行项目的自动化维护工具。

它的目标不是简单地“自动 rebase”，而是帮助你维护一条自己的产品线：

```text
上游项目
  -> 自用增强版分支
  -> 可投稿给上游的干净 PR 分支
```

典型场景：

- 你基于某个开源项目长期维护自己的增强版。
- 某些功能想放进自用分支，但不一定会被上游接受。
- 某些功能想单独拆成 PR 分支投稿给上游。
- 上游经常更新，你希望无冲突时自动同步，有冲突时让 AI 分析并通知你。

TermiteRS 的主场景是个人自用定制分支长期跟随上游，不是多人商业协作平台，也不是复杂 PR 队列管理器。`product` 分支是主要维护对象；`pr` 分支更多是测试同步流程，或偶尔拆出单功能补丁投稿上游。

项目保护功能以实际项目为最小单元，统一接收依赖公告、上游提交、用户转发文章和生产异常等安全信号。第一阶段已经提供不会执行项目代码的 Cargo 构建前静态门禁、结构化 Finding、SQLite 去重和 GitHub Issue 草稿；自动发送、候选修复和部署仍保持关闭。

## 当前能力

- 拉取上游和 fork 远端。
- 按配置维护多个分支。
- 支持 `rebase` 或 `merge` 到上游基线。
- 每个分支可配置独立测试命令。
- 同步成功后推送到 fork。
- 发生冲突时收集冲突文件、`git status`、`git diff --cc`。
- 可调用 OpenAI-compatible 接口分析冲突，例如 DeepSeek；低风险冲突可自动生成局部候选并在测试后继续同步。
- 可通过通知通道发送失败报告。
- 支持 QQ SMTP 和 Cloudflare Email Service。
- 同步命令和后台 worktree 会在测试、构建、推送前只读检查 Cargo 锁文件、清单和 `build.rs`；扫描失败或命中阻断项都会关闭后续执行。
- `rust` 规则包会直接从固定的 crates.io 静态域名获取 Cargo.lock 锁定归档，核对 SHA-256 后在内存中限制路径、条目数和展开大小，只读取清单与构建脚本，不调用 Cargo 或执行依赖代码。
- 可从 GitHub fork 远端自动推导投送目标，为阻断项生成需要人工批准的 Issue 草稿，不会自动发送。
- 启用项目保护后，每次同步会对 `before..HEAD` 的每个新 commit 调用 DS 做独立结构化审计；提交证据不能修改安全目录或自动化权限，重复 SHA 按项目策略指纹去重。

功能性冲突会保留在隔离 worktree 中，等待用户在维护看板选择方案、检查候选 diff 并确认应用。

## 提交规则

项目 commit 使用 `x.y.z 简短说明` 格式，例如：

```text
1.0.0 拆分服务模块
```

- `x.y.z` 从 `1.0.0` 重新计数。
- 简短说明只写本次提交最核心的变化，尽量控制在 15 个中文字符以内。

## 使用方式

推荐优先使用 Docker。这样 Git、SSH、Python 等基础工具都由镜像固定，宿主机不用处理乱七八糟的 Git 版本。

### Docker 运行

复制环境变量模板：

```powershell
Copy-Item .env.example .env
```

然后编辑 `.env`，填入 DeepSeek、QQ SMTP 或 Cloudflare 的密钥，并设置 SSH key 目录：

```env
TERMITE_SSH_DIR=C:\Users\your-name\.ssh
```

说明：

- Docker 镜像内置 `git`、`ssh`、`python3` 和 TermiteRS。
- `TERMITE_SSH_DIR` 会只读挂载到容器的 `/root/.ssh`。
- 这个 SSH key 必须已经授权到你的 GitHub 账号，或者是有 fork 推送权限的 deploy key。
- `.env` 已加入 `.gitignore`，不要提交到仓库。

构建镜像：

```powershell
docker compose build
```

一键检查运行环境：

```powershell
docker compose run --rm termiters doctor --config /app/termite.yml
```

查看状态：

```powershell
docker compose run --rm termiters status --config /app/termite.yml
```

试运行同步：

```powershell
docker compose run --rm termiters sync --config /app/termite.yml --dry-run
```

实际同步：

```powershell
docker compose run --rm termiters sync --config /app/termite.yml
```

后台常驻：

```powershell
docker compose run --rm termiters daemon --config /app/termite.yml
```

无参数启动会进入交互式 AI 助理入口：

```powershell
docker compose run --rm termiters
```

只同步某个分支：

```powershell
docker compose run --rm termiters sync --config /app/termite.yml --branch my/project
```

测试通知通道：

```powershell
docker compose run --rm termiters notify-test --config /app/termite.yml --subject "test" --body "hello"
```

如果机器上是旧版 Docker Compose，命令可能是 `docker-compose` 而不是 `docker compose`。

### 本机运行

本机运行需要你自己保证：

- 已安装 Rust。
- 已安装 Git。
- Git 版本建议 2.20 或更新。
- 当前机器的 GitHub SSH 授权可用。
- `termite.yml` 里的 repo 路径是本机真实路径。

一键检查：

```powershell
cargo run -- doctor --config termite.yml
```

生成示例配置：


```powershell
cargo run -- example-config > termite.yml
```

查看状态：

```powershell
cargo run -- status --config termite.yml
```

试运行同步：

```powershell
cargo run -- sync --config termite.yml --dry-run
```

实际同步：

```powershell
cargo run -- sync --config termite.yml
```

手动 `sync` 会发送项目级总结邮件，即使本次没有上游更新。

后台常驻：

```powershell
cargo run -- daemon --config termite.yml
```

daemon 自动触发的周期检查只有在出现上游更新、推送变更、失败或冲突时才发送邮件；如果只是无变化自检，不会发邮件。

无参数启动会进入交互式 AI 助理入口：

```powershell
cargo run
```

在助理内可以输入 `/check` 执行 `doctor` 和 `sync --dry-run`，输入 `/sync` 执行 `doctor` 和正式同步，输入 `/daemon` 启动常驻核心，输入 `/once` 运行一次同步，输入 `/exit` 退出。

显式启动助理：

```powershell
cargo run -- assistant --config termite.yml
```

测试通知通道：

```powershell
cargo run -- notify-test --config termite.yml --subject "test" --body "hello"
```

部署到服务器时，建议用 cron 或 systemd timer 定时执行 `sync`，不要一开始就做常驻服务。这样在 512MB 小机器上更稳。
如果需要实时常驻，可以使用 `daemon` 子命令；它会按配置间隔执行同步。连续失败达到阈值后会以失败状态退出，由配置了 `Restart=on-failure` 的 systemd 等进程管理器自动重启，避免调度器静默永久停止。

## 配置示例

```yaml
repo:
  path: D:\projects\your-project
  upstream: git@github.com:upstream-owner/project.git
  fork: git@github.com:your-name/project.git
  base_branch: master
  upstream_remote: origin
  fork_remote: fork

protection:
  enabled: true
  project:
    name: your-project
    description: |
      这是一个公开运行的项目。
      RCE、认证绕过、任意文件读写和供应链恶意代码必须立即阻止。
  profiles: [baseline, rust]
  automation: candidate

branches:
  - name: fix/dead-character-switch
    kind: pr
    note: 测试样本分支；可用于单功能投稿，但不是长期维护复杂 PR 队列的主场景。
    sync: rebase
    push: force-with-lease
    tests:
      - python -m py_compile src\task\BaseCombatTask.py src\task\AutoCombatTask.py tests\TestChar.py

  - name: my/project
    kind: product
    note: 个人自用主分支，允许混合多个个人补丁，优先保证持续跟随上游。
    sync: rebase
    push: force-with-lease
    tests:
      - python -m py_compile src\task\BaseCombatTask.py src\task\AutoCombatTask.py src\char\Aemeath.py src\char\Linnai.py
    # 发布分支应至少包含一个 unittest/pytest 或项目自定义行为测试命令。
    require_behavioral_tests: true
    release:
      enabled: true
      tag_prefix: v99.0.
    auto_resolve:
      enabled: false
      max_rounds: 5
      max_conflict_files: 1
      max_file_bytes: 40960
      require_tests: true
      allowed_paths:
        - src/char/

daemon:
  interval_seconds: 1800
  jitter_seconds: 120
  run_on_start: true
  max_consecutive_failures: 3
```

项目保护配置只描述人的意图：

- `profiles` 引用程序维护的安全基线，项目无需展开一长串规则。
- `baseline` 对通用不可接受漏洞和 P0/P1 失败关闭，增加 `strict` 后 P2 也进入自动阻断阈值；是否影响当前项目和生产可达性仍单独记录。
- `description` 使用自然语言说明业务、关键资产和不可接受的风险。
- `automation: candidate` 允许准备隔离候选，但不授权推送、合并、发布或部署。
- 仓库源码、依赖和提交信息都属于不可信证据，不能借此修改安全基线或自动化权限。
- `rust` 规则包无法无执行取证的私有注册表或 Git 外部依赖会失败关闭；需要先增加对应的受限证据适配器，不能自动跳过。
- DS 会同时判断“隐藏安全修复”和“新引入风险”；隐藏修复必须给出 FixContract，沙箱测试通过后还会由独立提示检查最终候选差异、安全属性、脆弱行为和回归证据，任一项缺失都不会推送。
- 项目保护启用后，配置中的测试命令只会在 Linux Bubblewrap 沙箱执行：网络、宿主环境变量、SSH/邮件/DS 凭证和宿主根目录均不可见；沙箱缺失时失败关闭。

构建前静态扫描：

```bash
cargo run -- protect scan --config termite.yml
```

扫描指定的离线依赖展开目录，并准备 Issue 草稿：

```bash
cargo run -- protect scan --config termite.yml \
  --path ./dependency-snapshot \
  --issue-repository owner/project
```

输出是结构化 JSON。发现阻断项时命令返回退出码 `2`，并且不会运行 `cargo build`、`cargo test`、`build.rs` 或任何项目脚本。配置 `protection.enabled: true` 时，正常同步和后台服务也会在首个测试命令前执行同一门禁；信号、Finding 和 Issue 草稿会幂等保存到 `service.data_dir/termite.db`，重复扫描不会重复创建草稿。GitHub 远端会从 `repo.fork` 自动识别，也可以在手动扫描时用 `--issue-repository` 明确指定。

调查人工保存的安全公告或社交媒体消息：

```bash
cargo run -- protect investigate --config termite.yml \
  --summary "某依赖出现严重漏洞" \
  --reference "https://example.com/advisory" \
  --content-file ./advisory.txt \
  --branch my/project
```

`--reference` 只作为证据保存，TermiteRS 不会访问该地址，避免公告内容把程序诱导到内网或恶意下载地址。DS 第一阶段只能从受控 Git 文件索引中选择最多三个普通文件；第二阶段只能基于这些文件给出判断和完整文件候选。`automation: observe` 只调查和告警；`candidate` 才会在隔离 worktree 写候选，并依次经过静态门禁、无网络 Bubblewrap 行为测试、候选提交安全审计和独立 FixContract 验证。即使全部通过，也不会自动推送、创建 PR、发布或部署。

分支类型建议：

- `kind: pr`：单功能 PR 分支，保持改动干净。
- `kind: product`：自用总分支，可以包含多个功能。
- `note`：用户备注，说明分支用途。AI 总结邮件和后续配置助理会参考这个字段。

自动发布标签：

- `release.enabled: true` 后，仅在同步、测试和分支推送成功后发布标签。
- `tag_prefix: v99.0.` 会按远端已有标签递增，例如 `v99.0.0` 后发布 `v99.0.1`。
- 当前提交已有同前缀标签时不会重复发布；标签只新增，不覆盖旧标签。
- `push: none` 与自动发布互斥，`doctor` 会将这种配置判为失败。

自动修冲突：

- `auto_resolve.enabled: true` 后，TermiteRS 会解析 rebase/merge 的冲突块，只把双方内容、少量相邻上下文和块哈希交给 LLM。
- LLM 只返回每个冲突块的局部替换。TermiteRS 会校验路径、块编号和 SHA-256，再在本地重建完整文件，未冲突区域不会由模型重新生成。
- 只有 LLM 返回 `risk: low`、完整解决全部冲突块且路径在 `allowed_paths` 内时，才会写回文件并继续同步。
- `max_file_bytes` 现在限制发送给 LLM 的结构化冲突块总大小，不再按照整个源文件大小拒绝自动处理。
- `require_tests: true` 时，自动修复后必须有测试命令并全部通过，否则不会推送。
- `require_behavioral_tests: true` 时，仅配置 `py_compile`/`compileall` 会阻止同步和发布；至少还要配置一个单元测试、集成测试或自定义冒烟测试命令。
- 这个功能适合低风险兼容性修复，不适合语义复杂、重构型或多文件大冲突。

## AI 助理

配置助理资料放在 `agents/termite-config/`。

当前 `assistant` 已经接入交互式入口。默认无参数启动会进入助理，用户可以用自然语言描述配置需求；在信息明确且用户确认后，助理可以修改 TermiteRS 自己工作目录内的配置文件。

关键规则：

- TermiteRS 优先维护个人自用 `product` 分支。
- `pr` 分支只是辅助场景，不默认长期维护复杂 PR 队列。
- 修改 `push` 策略前，必须让用户明确回答“本地测试”或“远端历史”。
- AI 不允许读取或输出 `.env` 中的密钥原文。
- AI 不拥有宿主机任意文件权限。自然语言触发的配置写入只允许落在 TermiteRS 当前工作目录内。
- AI 不开放任意 shell 执行。需要本地检查时，只允许触发内置动作，例如 `doctor` 和 `sync --dry-run`。
- 配置变更后必须先跑 `doctor` 和 `sync --dry-run`。

## LLM 配置

LLM 使用 OpenAI-compatible Chat Completions 协议。DeepSeek 只是一个内置 provider，也可以接 OpenAI 或其他兼容服务。

```yaml
llm:
  enabled: true
  provider: deep-seek
  model: deepseek-v4-flash
  api_key_env: DEEPSEEK_API_KEY
  temperature: 0.1
  max_prompt_bytes: 81920
  prompts:
    # 可用占位符：{branch}、{base}、{conflict_files}、{git_status}、{combined_diff}
    conflict_system: |
      你是一个严谨的软件分支维护助手。请分析 Git rebase/merge 冲突，判断是机械冲突还是功能冲突，并给出安全处理建议。
    conflict_user: |
      请分析下面的冲突。

      分支：{branch}
      基线：{base}
      冲突文件：
      {conflict_files}

      结构化冲突块：
      {conflict_blocks}

      Git 状态：
      {git_status}

      Combined diff：
      {combined_diff}
    # 可用占位符：{branch}、{base}、{conflict_files}、{git_status}、{combined_diff}、{conflict_blocks}
    # 旧 {file_contents} 仍可使用，但内容也会替换成结构化冲突块，不再提供完整文件。
    auto_resolve_system: |
      你是一个谨慎的软件维护助手。你只能做低风险兼容性冲突修复。必须只输出 JSON，不要 Markdown，不要解释。
    auto_resolve_user: |
      请分析下面的 Git 冲突，并仅在低风险时返回每个冲突块的 replacement。
      必须原样返回 path、conflict_id 和 expected_sha256。
      如果风险不是 low，resolutions 必须为空。

      分支：{branch}
      基线：{base}
      冲突文件：
      {conflict_files}

      Git 状态：
      {git_status}

      Combined diff：
      {combined_diff}
    # 可用占位符：{report}
    sync_summary_system: |
      你是一个严谨的软件分支维护助手。请只根据同步报告做中文总结。输出必须是纯文本，不要使用 Markdown、加粗、标题或代码块。
    sync_summary_user: |
      请总结下面这次 TermiteRS 同步报告，控制在 5 条以内。
      输出纯文本，不要使用 Markdown、加粗、标题或代码块。

      同步报告：
      {report}
```

DeepSeek V4 Flash 的 API 模型 ID 是 `deepseek-v4-flash`。如果后续模型名变化，只需要改 `model` 字段。

如果使用自定义兼容接口：

```yaml
llm:
  enabled: true
  provider: open-ai-compatible
  base_url: https://example.com/v1
  model: your-model
  api_key_env: YOUR_API_KEY
```

API Key 不要写进配置文件，放到环境变量里。

## 通知配置

通知支持多个通道：

- `smtp`：QQ、163、Gmail、企业邮箱等。
- `cloudflare-email-service`：Cloudflare Email Service API。

推荐策略是：

```yaml
policy:
  mode: primary-with-fallback
```

含义是按顺序尝试通道，前一个失败再走下一个。实际使用上可以 Cloudflare 优先，QQ SMTP 兜底。

### QQ 邮箱 SMTP

QQ 邮箱适合作为 SMTP 发信方。常用配置：

```yaml
notify:
  enabled: true
  subject_prefix: "[TermiteRS]"
  events:
    sync_start: false
    sync_summary: true
  policy:
    mode: primary-with-fallback
  channels:
    - name: qq
      kind: smtp
      enabled: true
      smtp_host: smtp.qq.com
      smtp_port: 465
      tls: implicit
      username_env: QQ_SMTP_USER
      password_env: QQ_SMTP_AUTH_CODE
      from: your@qq.com
      to:
        - your@qq.com
```

说明：

- `QQ_SMTP_USER` 是 QQ 邮箱地址。
- `QQ_SMTP_AUTH_CODE` 是 QQ 邮箱 SMTP 授权码，不是 QQ 密码。
- 授权码只应放在服务器环境变量里，不要提交到仓库。
- `events.sync_start: true` 会在每个分支开始同步前发送“正在合并”通知，一般只建议调试时打开。
- `events.sync_summary: true` 会在每次同步结束后调用 LLM 生成中文总结，并发送一封项目级总结邮件。开启它时，分支失败/冲突也会汇总在这封邮件里。

### Cloudflare Email Service

Cloudflare Email Routing 主要是收信转发，不是 SMTP 发信服务。要通过 Cloudflare 发信，应使用 Cloudflare Email Service，并且需要 Cloudflare 账号、域名和 API Token。

```yaml
notify:
  enabled: true
  subject_prefix: "[TermiteRS]"
  events:
    sync_start: false
    sync_summary: true
  policy:
    mode: primary-with-fallback
  channels:
    - name: cloudflare
      kind: cloudflare-email-service
      enabled: true
      api_token_env: CLOUDFLARE_API_TOKEN
      account_id_env: CLOUDFLARE_ACCOUNT_ID
      from: termite@example.com
      to:
        - your@qq.com

    - name: qq
      kind: smtp
      enabled: true
      smtp_host: smtp.qq.com
      smtp_port: 465
      tls: implicit
      username_env: QQ_SMTP_USER
      password_env: QQ_SMTP_AUTH_CODE
      from: your@qq.com
      to:
        - your@qq.com
```

没有 Cloudflare 发信能力时，把 Cloudflare 通道设为 `enabled: false`，只用 QQ SMTP。

## 同步策略

可选策略：

- `rebase`：PR 分支推荐使用，历史干净。
- `merge`：自用分支可以考虑使用，冲突少时更省心。

推送策略：

- `force-with-lease`：rebase 后推荐使用，比普通 force push 安全。
- `normal`：普通 push。
- `none`：只本地同步，不推送。

## 当前限制

- AI 只能生成冲突块局部替换，不能直接修改非冲突文件；复杂修改仍需人工处理。
- 模型暂时不能主动请求额外文件或指定行号范围的上下文。
- Cloudflare 通道按 Email Service API 设计，不支持把 Email Routing 当 SMTP 发件人。
- 项目保护已经支持 crates.io 锁定依赖取证、DS 逐提交分类和项目命令沙箱；私有注册表和 Git 依赖仍会失败关闭，FixContract 独立验证与候选修复生成仍在后续节点。
- 受保护项目的自动执行目前要求 Linux 安装 `bubblewrap`；Windows 必须从 WSL/Linux 运行，不能降级为宿主 PowerShell。沙箱只挂载 worktree 和系统运行时，因此测试依赖必须位于项目目录或系统只读运行时中。
- FixContract 独立验证与 DS 主动生成非冲突安全补丁仍在后续节点。
- GitHub 功能当前只准备结构化 Issue 草稿，不调用 GitHub 写接口。

## 协作看板服务

`serve` 子命令通过 Unix Socket 为博客后台提供受限接口：

```bash
termiters serve --config /etc/termiters/termite.yml
```

服务使用 SQLite 保存任务、对话、候选修改和通知状态。每次正式同步都在独立 detached worktree 中执行。低风险冲突继续按原规则自动处理；功能性冲突会保留现场，等待后台多轮指导。

同机同时运行 `serve` 与 `daemon` 时，两者职责不同：`daemon` 只负责定时调度，检测到 `service.socket_path` 后会通过内部 Unix Socket 创建任务并等待结果；`serve` 负责实际同步、测试、推送、冲突处理和 SQLite 记录。这样自动同步也会进入看板统计，并与后台手动任务共用仓库锁。没有服务 Socket 的旧部署仍由 `daemon` 直接同步。常驻调度即使没有发现更新也会留下已完成任务记录，但不会发送无更新邮件；主动执行 `daemon --once` 或后台手动同步仍会通知。

推送行为统一遵循以下规则：

- 无冲突同步，或被判定为低风险且测试通过的自动解冲突，会按分支的 `push` 策略直接推送。
- 功能性冲突由人工选择方案并应用后，只要测试通过，也会立即按分支的 `push` 策略自动推送。
- 所有推送都会重新获取 fork 远端 SHA；远端已发生变化时拒绝覆盖，并在看板保留“重新推送”入口。

```yaml
service:
  socket_path: /run/termiters/termiters.sock
  data_dir: /var/lib/termiters
  public_dashboard_url: https://blog.example.com/admin/termite
```

- GitHub Deploy Key、DeepSeek Key 和 SMTP 凭证只能由 `termiters` 用户读取。
- 博客只通过 Unix Socket 调用固定动作，不读取仓库或密钥。
- Dashboard 和任务接口会返回仓库路径、远端地址、任务输出、人工对话、候选 diff 和冲突上下文，只能提供给可信后台，不要直接暴露到公网。
- TermiteRS API 只能通过本机 Unix Socket 访问；博客后台使用自己的管理员会话和 CSRF 校验代理固定动作，不要把 `/v1/*` 直接代理到公网。
- `deploy/` 提供 systemd、tmpfiles 和 Nginx 示例。
- 如果测试命令本身需要特殊环境，需要在配置里写清楚。

## 后续计划

- 支持模型按需请求有限范围的只读上下文。
- 增加更多语言的语法级候选校验。
- 增加冲突报告落盘。
- 增加 Webhook 通道，例如飞书、钉钉、企业微信。
- 增加多仓库配置。
