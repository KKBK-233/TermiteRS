# TermiteRS

TermiteRS 是一个用于维护长期 fork 分支的自动化工具。

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

## 当前能力

- 拉取上游和 fork 远端。
- 按配置维护多个分支。
- 支持 `rebase` 或 `merge` 到上游基线。
- 每个分支可配置独立测试命令。
- 同步成功后推送到 fork。
- 发生冲突时收集冲突文件、`git status`、`git diff --cc`。
- 可调用 OpenAI-compatible 接口分析冲突，例如 DeepSeek。
- 可通过通知通道发送失败报告。
- 支持 QQ SMTP 和 Cloudflare Email Service。

当前版本只让 AI 做冲突分析和处理建议，不会自动应用 patch。

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

后台常驻：

```powershell
cargo run -- daemon --config termite.yml
```

无参数启动会进入交互式 AI 助理入口：

```powershell
cargo run
```

在助理内可以输入 `/daemon` 启动常驻核心，输入 `/once` 运行一次同步，输入 `/exit` 退出。

显式启动助理：

```powershell
cargo run -- assistant --config termite.yml
```

测试通知通道：

```powershell
cargo run -- notify-test --config termite.yml --subject "test" --body "hello"
```

部署到服务器时，建议用 cron 或 systemd timer 定时执行 `sync`，不要一开始就做常驻服务。这样在 512MB 小机器上更稳。
如果需要实时常驻，可以使用 `daemon` 子命令；它会按配置间隔执行同步，连续失败达到阈值后停止。

## 配置示例

```yaml
repo:
  path: D:\projects\your-project
  upstream: git@github.com:upstream-owner/project.git
  fork: git@github.com:your-name/project.git
  base_branch: master
  upstream_remote: origin
  fork_remote: fork

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

daemon:
  interval_seconds: 1800
  jitter_seconds: 120
  run_on_start: true
  max_consecutive_failures: 3
```

分支类型建议：

- `kind: pr`：单功能 PR 分支，保持改动干净。
- `kind: product`：自用总分支，可以包含多个功能。
- `note`：用户备注，说明分支用途。AI 总结邮件和后续配置助理会参考这个字段。

## AI 助理

配置助理资料放在 `agents/termite-config/`。

当前 `assistant` 已经接入交互式入口。默认无参数启动会进入助理，用户可以用自然语言描述配置需求；第一版只输出配置建议，不直接覆盖文件。

关键规则：

- TermiteRS 优先维护个人自用 `product` 分支。
- `pr` 分支只是辅助场景，不默认长期维护复杂 PR 队列。
- 修改 `push` 策略前，必须让用户明确回答“本地测试”或“远端历史”。
- AI 不允许读取或输出 `.env` 中的密钥原文。
- 配置变更后必须先跑 `doctor` 和 `sync --dry-run`。

## LLM 配置

LLM 使用 OpenAI-compatible Chat Completions 协议。DeepSeek 只是一个内置 provider，也可以接 OpenAI 或其他兼容服务。

```yaml
llm:
  enabled: true
  provider: deep-seek
  model: deepseek-v4-pro
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

      Git 状态：
      {git_status}

      Combined diff：
      {combined_diff}
    # 可用占位符：{report}
    sync_summary_system: |
      你是一个严谨的软件分支维护助手。请只根据同步报告做中文总结。
    sync_summary_user: |
      请总结下面这次 TermiteRS 同步报告，控制在 5 条以内。

      同步报告：
      {report}
```

DeepSeek V4 Pro 的 API 模型 ID 是 `deepseek-v4-pro`。如果后续模型名变化，只需要改 `model` 字段。

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

- AI 目前只分析冲突，不自动改代码。
- 邮件只在同步失败或冲突时作为通知渠道使用。
- Cloudflare 通道按 Email Service API 设计，不支持把 Email Routing 当 SMTP 发件人。
- 如果测试命令本身需要特殊环境，需要在配置里写清楚。

## 后续计划

- 让 AI 生成 patch，但默认不自动应用。
- 增加“只允许修改冲突文件”的安全限制。
- 增加冲突报告落盘。
- 增加 Webhook 通道，例如飞书、钉钉、企业微信。
- 增加多仓库配置。
