<div align="center">

<img src="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/agentdetox-mark.svg" alt="AgentDetox — 守护智能体持久上下文的盾牌" width="96" height="96">

# AgentDetox

### 检查智能体保存的内容，发现变更，恢复先前版本。

为编程智能体跨会话信任的记忆、指令、技能和配置提供检查、监测与恢复。

[![PyPI](https://img.shields.io/pypi/v/agentdetox?color=16836b)](https://pypi.org/project/agentdetox/)
[![CI](https://github.com/chriswu727/agentdetox/actions/workflows/ci.yml/badge.svg)](https://github.com/chriswu727/agentdetox/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/agentdetox)](https://pypi.org/project/agentdetox/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[快速开始](#快速开始) · [工作方式](#工作方式) · [验证与边界](#验证与边界) · [文档索引](docs/README.md)

[English (primary)](README.md) · **简体中文**

</div>

---

网页里的投毒内容可能成为明天的记忆。依赖的安装脚本也可能在智能体执行任务时修改 `CLAUDE.md`。
AgentDetox 检查持久上下文的写入，记录变更及来源证据，让你查看差异并恢复先前版本。

**0.4.1 已发布**至 [PyPI](https://pypi.org/project/agentdetox/0.4.1/) 和
[GitHub](https://github.com/chriswu727/agentdetox/releases/tag/v0.4.1)。项目仍处于**预览阶段**：
Claude Code 是受支持的集成，Codex 和 Cursor 钩子属于实验功能；OpenClaw 没有自己的钩子，写入时不会被实时检查，
其文件可通过命令行检查，也会在其他客户端的会话开始时被比对。
开发环境支持原生 Windows（Python 3.12 + Git Bash）以及 macOS/Linux。
Windows 已完成安装包生命周期的本机离线验证；真实客户端验收和长期日常使用验证分别记录，
详见 [Windows 验证记录](docs/windows-validation.md)。
原生 Windows 的延迟实测仍有多项超出既定预算；[性能记录](bench/HOOK_LATENCY.md)
保留失败数据和优化前后的交替对照结果。

<p align="center">
<picture>
<source media="(max-width: 600px)" srcset="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/workflow-mobile.svg">
<img src="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/workflow.svg" alt="检查写入 → 发现变更 → 查看差异和来源证据 → 备份后恢复先前版本" width="880">
</picture>
</p>

## 快速开始

需要 **Python 3.11+**。使用 [uv](https://docs.astral.sh/uv/) 或 `pipx` 安装：

Windows 上请安装 Git for Windows，供 Claude 的 Bash 工具使用。下面的 CLI 命令可以从
PowerShell 启动，但 AgentDetox 的 shell 写入分析支持 Git Bash 语法，尚不支持 PowerShell/cmd.exe
语法。Windows 的可选 NLI 使用后台 worker，没有常驻模型服务。
原生 Windows 开发命令见 [贡献指南](CONTRIBUTING.md#setup-and-checks)。

```bash
uv tool install agentdetox
agentdetox demo
```

演示会在临时目录调用真实钩子处理程序：拒绝一条投毒写入，发现 shell 操作造成的篡改，然后恢复文件。
**不会调用模型，也不消耗智能体订阅额度。**

接入 Claude Code 时，选择以下**一种**方式：

<details open>
<summary><b>Claude Code 插件</b></summary>

在终端执行：

```bash
claude plugin marketplace add chriswu727/agentdetox
claude plugin install agentdetox@agentdetox
```

插件优先使用已安装的 `agentdetox`。没有本地命令时，需要 `uvx` 从 PyPI 获取并运行插件固定的版本。
先安装上面的 CLI，也能直接使用审核和恢复命令。

</details>

<details>
<summary><b>直接注册 Claude Code 设置钩子</b></summary>

```bash
agentdetox install claude-code --apply
```

命令会先备份再修改 Claude Code 设置，并遵循 `CLAUDE_CONFIG_DIR`。这是插件方式的替代方案，避免两者同时启用。

</details>

重启 Claude Code，然后检查安装：

```bash
agentdetox doctor
agentdetox status
```

`doctor` 会报告缺失、过时或重复的钩子。首次会话先扫描已有上下文，再记录恢复检查点。
[完整安装、升级与卸载说明（英文）→](docs/user-guide.md#install)

## 工作方式

1. **写入前检查：**检查计划中的 Write/Edit 内容和可识别的 shell 写入。高风险规则命中会被拒绝；
   如果可疑文本由你自己提供，则请求确认，隐藏文本仍会被拒绝。修改钩子、MCP 服务、权限等防护配置需要授权。
2. **写入或 shell 工具结束后记录：**保存版本与来源证据。shell 工具成功或失败都会触发限定范围的比较，
   并为上下文变更发出审核提示。这只能说明变更发生在该工具运行期间，不能证明具体由哪个进程写入。
3. **会话开始时核对：**检查智能体之外的修改。命中规则的内容会持续提示，直到完成审核；新增的可执行配置提示一次，随后仍留在审核列表中。
4. **审核时处理：**查看差异和证据，接受该确切版本、忽略单条发现，或恢复到某次变更之前。
   恢复会检查文件是否又被修改，并先备份当前文件。

Claude 上下文覆盖 `CLAUDE.md`、父目录指令、自动记忆、规则、技能、子智能体、命令、输出风格、
钩子脚本、设置和 MCP 配置。检测规则覆盖英文和中文。
[完整覆盖范围与行为（英文）→](docs/user-guide.md#what-it-does-in-claude-code)

### 从提示到处理

```bash
agentdetox review --interactive           # 在终端浏览当前项目的文件
agentdetox review --project . --since 7d  # 最近的项目和自动记忆变更
agentdetox review C42                    # 查看审核列表里的变更编号
agentdetox restore C42                   # 预览恢复到此次变更之前的版本
agentdetox restore C42 --apply           # 备份当前文件后执行恢复
```

`C42` 是示例编号，请替换为自己的审核列表中显示的编号。接受版本或忽略发现，都不会永久信任某个来源。
恢复针对**整个历史版本**，可能同时撤销其中的正常修改。对于新增配置项，使用原先添加它的工具移除，通常比恢复整个配置文件更合适。

`agentdetox clean C42` 列出此次变更新增的行。
使用 `agentdetox clean C42 --lines 3,5-7` 预览仅删除自己选中的记忆、指令或技能文本，保留其他内容和无冲突的后续修改。
审核后执行预览输出的完整应用命令；文件发生新变化时，旧预览会失效。清除会先备份当前文件，再扫描结果。
清除只修改磁盘上的文件，不会改变已在运行的会话中已读入的内容：请在相应客户端开启新会话后再依赖清除结果。
它不会自动把复制来的内容当作投毒，也不会恢复被覆盖的旧文本或判断事实真伪。终端交互审核也提供此操作。
[审核、设置与恢复细节（英文）→](docs/user-guide.md#day-to-day)

## 验证与边界

AgentDetox 提供检查和恢复，**不构成安全边界，也不验证事实真伪**。改写后的投毒内容、看似可信的虚假事实可能通过。
任意脚本和动态生成的路径可能绕过执行前检查，限定范围的工具结束后比较可以发现仍然存在的变更；
工具返回后的后台写入需要稍后核对。钩子自身出错时会放行操作，错误保留在 `doctor` 和 `status` 中。
以当前用户身份运行的代码可以修改钩子或存储。

- **离线回归集：**人工编写的防范、监测和逐字节恢复案例，另有 21 个独立编写的验收案例，
  保留其中三个明确的语义漏检；不代表真实世界准确率。
  [方法与结果](bench/ACCURACY.md)。
- **真实 Claude Code 实验，2026-11-09：**两个开发验收场景最终通过，共使用 4 次会话；保留两次流畅使用
  检查失败，并说明了编辑工具场景的提示澄清。这是对 0.4.1 十场景验收的补充，并非完整重跑。
  防护成功和用户任务完成分别报告。[实验结果](lab/results/latest.md)。
- **开发版延迟，2026-11-10：**单台 Mac、不含 NLI 推理、每项 100 个样本，最新的库存空闲状态测量通过原有 12 项预算。
  Bash 前后钩子合计 P95 **110.3 ms**；启动检查 1,000 份未变化文件 **123.0 ms**；
  四路并发写入加 Bash 前后检查 **273.4 ms**。此前的扫描负载测量和 Windows 超预算记录仍保留。
  [方法、原始数据和限制](bench/HOOK_LATENCY.md)。
- **十万文件合成库存，2026-11-10：**全量与增量检查、取消续扫、限定版本的忽略与撤销均通过验收。
  约 419 MB 笔记首次检查 **316 秒**，未变化增量检查 **15.3 秒**，进程峰值内存 **46.8 MB**。
  已知语义漏检仍保留；这是本地模块测量，不代表生产规模支持或真实世界准确率。
  [方法与原始报告](bench/LARGE_MEMORY.md#100k-completion-and-scoped-triage)。

来源匹配只能提供文本复制证据，不能证明恶意意图或作者身份。恢复后扫描没有发现，也不能证明文件安全。
开发分支 `main` 上的 `agentdetox library` 可检查已有的记忆文件夹并清理经审核的行，
按照独立的[规模验收标准](bench/LARGE_MEMORY.md)测量；其中 1 千、1 万、10 万文件档位并非当前生产支持承诺。
[完整限制（英文）](docs/user-guide.md#what-it-does-not-catch) · [威胁模型（英文）](SECURITY.md)

### 本地处理，历史记录仍需保护

钩子和检测不会联网，没有遥测或账号。安装、插件的 `uvx` 回退和可选模型下载需要网络。
文件副本和来源证据保存在 `~/.agentdetox`；配置文件副本可能包含密钥。备份时应包含整个存储及 `objects/`，
删除历史前先查看保留策略。[隐私与存储内容（英文）→](PRIVACY.md)

## 更多用法

- **其他智能体：**Codex、Cursor 的实验性钩子；没有 OpenClaw 插件，Cursor 尚未实际运行验证。在开发分支 `main` 上，`agentdetox agent inspect`
  会在各客户端实际存放（或迁移到）的位置查找 Claude Code、Codex、Cursor 和 OpenClaw 的记忆、规则与技能文件，
  并把被标记的内容记录为审核条目，因此无需任何钩子即可使用 `clean` 和 `restore`。它检查的是文件本身，
  不代表客户端一定会触发钩子，也不判断记忆内容是否属实。[集成矩阵（英文）](docs/user-guide.md#other-agents)。
- **矛盾检测：**可选本地 NLI，因仍有误报，默认在后台记录。[配置与限制（英文）](docs/user-guide.md#contradiction-detection-experimental)。
- **已有记忆库（开发分支 `main`）：**`agentdetox library scan <文件夹>` 为你指定的文件夹建立清单，
  用逐文件规则检查其中的文本文件，中断后可继续，且从不把文件报告为“干净”；`clean M<ID>` 删除经审核的行并保留备份，
  `library dismiss` 可只针对某个文件的当前内容搁置一条误报，而不将其加入全局允许列表。
  [记忆库指南（英文）](docs/user-guide.md#inspecting-a-library-of-memory-files)。
- **RAG 知识库：**`agentdetox scan` 检查隐藏指令和可疑段落簇；`trace` 为错误答案提供排查线索排序。[扫描器指南（英文）](docs/user-guide.md#also-scanning-a-rag-knowledge-base)。

## 文档与开发

[文档索引](docs/README.md) · [用户指南](docs/user-guide.md) · [更新日志](CHANGELOG.md) ·
[路线图](ROADMAP.md) · [贡献指南](CONTRIBUTING.md)

```bash
./scripts/check.sh  # 代码规范、类型检查和测试
```

修改钩子或恢复流程前，请阅读[架构](docs/architecture.md)与[设计决策](docs/decisions.md)。
离线回归不调用模型；真实智能体实验需要明确授权和会话次数上限。

英文是默认文档语言。本页是中文入门，对应 0.4.1；详细指南、验证记录和发布说明以英文原文为准。
采用 [Apache-2.0](LICENSE) 许可证。
