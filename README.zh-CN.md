<div align="center">

<img src="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/agentdetox-mark.svg" alt="AgentDetox — 守护智能体持久上下文的盾牌" width="96" height="96">

# AgentDetox

### 保护智能体的记忆：拦截已知风险的写入，发现可疑变更，清理不想要的指令。

为编程智能体跨会话信任的记忆、指令、技能和配置提供保护。

[![PyPI](https://img.shields.io/pypi/v/agentdetox?color=16836b)](https://pypi.org/project/agentdetox/)
[![CI](https://github.com/chriswu727/agentdetox/actions/workflows/ci.yml/badge.svg)](https://github.com/chriswu727/agentdetox/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/agentdetox)](https://pypi.org/project/agentdetox/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[快速开始](#快速开始) · [工作方式](#工作方式) · [验证与边界](#验证与边界) · [文档索引](docs/README.md) · [交互演示](https://yichenwu.dev/projects/agentdetox)

[English (primary)](README.md) · **简体中文**

</div>

---

网页里的投毒内容可能成为明天的记忆。依赖的安装脚本也可能在智能体执行任务时修改 `CLAUDE.md`。
写进记忆、规则或技能的内容，之后每个会话都会被照做。AgentDetox 检查这些持久上下文的写入，
记录变更及来源证据，让你只删掉选中的新增行，或恢复先前版本，两种操作都会先备份。

**十秒试用，无需安装**（需要 [uv](https://docs.astral.sh/uv/)）：

```bash
uvx agentdetox demo          # 在临时目录里看一次攻击被拦截、被发现、被撤销
uvx agentdetox agent scan    # 只读：检查你的智能体已有的记忆、规则和技能
```

<p align="center">
<img src="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/demo.svg" alt="agentdetox demo 的节选输出：一次会执行网络下载代码的记忆写入被拦截；安装脚本对 CLAUDE.md 的修改被发现；文件恢复到先前版本，被篡改的副本保留在隔离区" width="880">
</p>

- **预防：**写入记忆、规则或技能的内容如果匹配已知攻击，在落盘前被拒绝；从智能体刚读过的网页或文件里照抄来的文本会先询问你。
- **检测：**智能体之外发生的修改（安装脚本、其他工具）会在 shell 工具结束后和下次会话开始时被发现。
- **清理：**查看差异和文本来源，只删除你选中的行，或恢复先前版本。任何删除都会先备份。清理改的是文件，
  不影响正在运行的会话已经读入的内容：清理后请开启新会话。
- **可选，默认关闭：**让一个小模型判断每次写入会让智能体做什么。在不参照规则写出的攻击文本上，
  它标记了 210 条中的 208 条，而规则本身只能拦住约三分之一
  （[测量与限制（英文）](bench/ACCURACY.md#a-model-as-judge-2026-11-10)）。

**0.6.0 已发布**至 [PyPI](https://pypi.org/project/agentdetox/0.6.0/) 和
[GitHub](https://github.com/chriswu727/agentdetox/releases/tag/v0.6.0)。项目处于**预览阶段**，
是一层检查与恢复，[不是安全边界](#验证与边界)。
[集成矩阵（英文）→](docs/user-guide.md#other-agents)

<p align="center">
<picture>
<source media="(max-width: 600px)" srcset="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/workflow-mobile.svg">
<img src="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/workflow.svg" alt="检查写入 → 发现变更 → 查看差异和来源证据 → 备份后恢复先前版本" width="880">
</picture>
</p>

## 快速开始

需要 **Python 3.11+**。使用 [uv](https://docs.astral.sh/uv/) 或 `pipx` 安装：

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

Windows 上请安装 Git for Windows：shell 写入分析读取 Git Bash 语法，不支持 PowerShell 或 cmd.exe
（[Windows 验证记录（英文）](docs/windows-validation.md)）。

`doctor` 会报告缺失、过时或重复的钩子。首次会话先扫描已有上下文，再记录恢复检查点。
[完整安装、升级与卸载说明（英文）→](docs/user-guide.md#install)

## 工作方式

1. **写入前检查：**检查计划中的 Write/Edit 内容和可识别的 shell 写入。高风险规则命中会被拒绝；
   如果可疑文本由你自己提供，则请求确认，隐藏文本仍会被拒绝。修改钩子、MCP 服务、权限等防护配置需要授权。
2. **写入或 shell 工具结束后记录：**保存版本与来源证据。shell 工具成功或失败都会触发限定范围的比较，
   并为上下文变更发出审核提示。这只能说明变更发生在该工具运行期间，不能证明具体由哪个进程写入。
3. **会话开始时核对：**检查智能体之外的修改。命中规则的内容会持续提示，直到完成审核；新增的可执行配置提示一次，随后仍留在审核列表中。
4. **审核时处理：**查看差异和证据，接受该确切版本、忽略单条发现、删除选中的新增行，或恢复到某次变更之前。
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

`agentdetox clean C42` 列出此次变更在记忆、指令或技能中新增的行；
`agentdetox clean C42 --lines 3,5-7` 预览仅删除这些行，其余内容保持不变。
执行预览输出的完整应用命令。清除会先备份文件，再重新扫描；
它不会替你选择要删的行，也不会恢复被覆盖的旧文本或判断内容真伪。
[审核、设置与恢复细节（英文）→](docs/user-guide.md#day-to-day)

## 验证与边界

AgentDetox 提供检查和恢复，**不构成安全边界，也不验证事实真伪**。改写后的投毒内容、看似可信的虚假事实可能通过。
任意脚本和动态生成的路径可能绕过执行前检查，限定范围的工具结束后比较可以发现仍然存在的变更；
工具返回后的后台写入需要稍后核对。钩子自身出错时会放行操作，错误保留在 `doctor` 和 `status` 中；但如果出错时正在检查的是对智能体上下文的写入，则改为询问。
以当前用户身份运行的代码可以修改钩子或存储。

以下是针对人工编写或合成案例的定期测量，不代表真实世界准确率，也不是生产规模支持承诺。

- **离线回归集：**人工编写的防范、监测和逐字节恢复案例，另有 21 个独立编写的验收案例，
  保留其中三个明确的语义漏检。
  [方法与结果（英文）](bench/ACCURACY.md)。
- **Claude Code 实测：**在 0.5.0 候选版上（2026-11-10），12 个场景分别在启用和未启用 AgentDetox 时运行，
  24 组检查通过 23 组。在 0.6.0 候选版上（2026-11-11），只运行启用 AgentDetox 的一组，12 个场景通过 9 个：
  五次运行中有一次，指向非默认软件包源的记忆写入被询问之后，后一次仍提到该源的记忆写入未经询问就通过了；
  另外两项失败分别源于客户端本身和模型本身。
  [结果（英文）](lab/README.md#060-candidate-2026-11-11)。
- **钩子延迟，2026-11-11：**单台 Mac、不含 NLI 推理、每项 100 个样本，在 0.6.0 候选版最后几次提交之前测量，
  12 项预算全部通过。Bash 前后钩子合计 P95 **109.1 ms**；启动检查 1,000 份未变化文件 **121.7 ms**；
  四路并发写入加 Bash 前后检查 **235.5 ms**。
  [原始数据](bench/results/hooks-0.6.0-2026-11-11.json) · [方法与限制（英文）](bench/HOOK_LATENCY.md)。
- **十万文件合成库存，2026-11-10：**全量与增量检查、取消续扫、限定版本的忽略与撤销均通过验收。
  约 419 MB 笔记首次检查 **316 秒**，未变化增量检查 **15.3 秒**，进程峰值内存 **46.8 MB**。
  [方法与原始报告（英文）](bench/LARGE_MEMORY.md#100k-completion-and-scoped-triage)。

来源匹配只能提供文本复制证据，不能证明恶意意图或作者身份。恢复后扫描没有发现，也不能证明文件安全。
[完整限制（英文）](docs/user-guide.md#what-it-does-not-catch) · [威胁模型（英文）](SECURITY.md)

### 本地处理，历史记录仍需保护

钩子和检测不会联网，只有一个需要你主动开启的例外：可选的模型判读（`config judge`，或 `agent inspect --judge`）会通过你的 Claude Code 把它读取的文本发送给模型。没有遥测或账号。安装、插件的 `uvx` 回退和可选模型下载需要网络。
文件副本和来源证据保存在 `~/.agentdetox`；配置文件副本可能包含密钥。备份时应包含整个存储及 `objects/`，
删除历史前先查看保留策略。[隐私与存储内容（英文）→](PRIVACY.md)

## 更多用法

- **其他智能体：**Codex、Cursor 的实验性钩子；没有 OpenClaw 插件，Cursor 尚未实际运行验证。`agentdetox agent inspect`
  会在各客户端实际存放（或迁移到）的位置查找 Claude Code、Codex、Cursor 和 OpenClaw 的记忆、规则与技能文件，
  并把被标记的内容记录为审核条目，因此无需任何钩子即可使用 `clean` 和 `restore`。它检查的是文件本身，
  不代表客户端一定会触发钩子，也不判断记忆内容是否属实。[集成矩阵（英文）](docs/user-guide.md#other-agents)。
- **模型判读（默认关闭）：**`agentdetox config judge ask` 让一个小模型读取每次写入记忆、规则和技能的新增文本，
  判断它会让智能体做什么；它能发现规则的固定措辞漏掉的内容，并且只会增加询问，不会取消其他检查。
  [代价与限制（英文）](docs/user-guide.md#a-models-reading-of-each-write-optional)。
- **矛盾检测：**可选本地 NLI，因仍有误报，默认在后台记录。[配置与限制（英文）](docs/user-guide.md#contradiction-detection-experimental)。
- **已有记忆库：**`agentdetox library scan <文件夹>` 为你指定的文件夹建立清单，
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

英文是默认文档语言。本页是中文入门，对应 0.6.0；详细指南、验证记录和发布说明以英文原文为准。
采用 [Apache-2.0](LICENSE) 许可证。
