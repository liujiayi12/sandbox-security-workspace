# AegisAgent 项目汇报说明

## 1. 项目定位

AegisAgent 是一个面向智能体安全测试的沙箱系统。它接收用户上传的智能体压缩包，自动完成文件解包、静态扫描、运行适配、容器化构建、动态攻击测试、证据收集和报告生成。

当前项目版本定位为 **AegisAgent 5.0**。相比早期只关注“能否运行智能体”的沙箱，当前版本更强调三件事：

- **泛化适配**：尽量识别不同语言、框架和仓库结构中的智能体入口。
- **安全检测**：结合静态能力识别与动态证据验证，发现提示注入、恶意 skill、工具污染、记忆污染、敏感信息泄露等风险。
- **可解释报告**：将扫描结果、动态行为和证据链组织成普通用户可阅读的 Markdown 报告。

## 2. 整体执行流程

### 2.1 用户上传阶段

用户通过前端上传待测试的智能体压缩包，并可选择是否提供 API KEY。前端支持选择 API 厂商，例如 OpenAI、DeepSeek 等，也允许选择“无 API KEY”。

如果用户提供 API KEY，系统可以进一步启用：

- 大模型辅助静态扫描
- 大模型辅助智能体搭建
- 大模型辅助动态攻击分析

前端显示 API KEY 时会以掩码方式展示，避免明文暴露。

### 2.2 解包与项目画像阶段

后端收到压缩包后，会先进行安全解包和基础检查，避免路径穿越、文件数量过多等风险。随后沙箱会对项目形成一个初步画像，包括：

- 使用的语言：Python、Node.js、Java、Go、Rust、PHP 等
- 可能的框架：LangChain、AutoGen、CrewAI、MCP、FastAPI、Express、Spring AI、LangChain4j 等
- 项目结构：单项目、多模块、monorepo、examples、docs、packages、apps 等
- 依赖声明：`package.json`、`pyproject.toml`、`requirements.txt`、`pom.xml`、`build.gradle`、`go.mod`、`Cargo.toml` 等
- 运行线索：README、Dockerfile、devcontainer、Nix、MCP 配置、LangGraph 配置等

这一阶段的目标是回答两个问题：

- 这个压缩包里是否真的包含可运行智能体？
- 如果可运行，最可能的入口在哪里？

### 2.3 静态扫描阶段

静态扫描会读取项目文件，识别潜在风险能力和可达攻击面。当前重点关注：

- 环境变量与密钥读取能力
- 网络请求与 webhook 外传能力
- 文件系统读写能力
- shell/process 执行能力
- MCP/tool/plugin/skill 相关接口
- memory、scheduler、持久化状态
- browser、email、GitHub、RAG、calendar、drive 等外部内容入口

静态扫描不会简单地把“存在危险能力”直接判为最高危，而是区分：

- `capability`：代码具备某种危险能力，但尚未证明会被利用。
- `reachable_surface`：危险能力可能通过某个接口或外部内容路径被触发。
- `observed_behavior`：动态测试中已经观察到实际危险行为。

这种分层可以降低误报。例如，一个智能体读取环境变量并不一定等于泄露密钥；只有当动态 sink、canary、持久化证据或工具调用证据出现时，才更适合升级为已验证高危。

### 2.4 适配与建造计划生成阶段

沙箱会根据静态扫描结果生成多个候选 BuildPlan，而不是只尝试一个入口。候选来源包括：

- 项目显式提供的 `sandbox.yaml`
- Dockerfile / docker-compose
- devcontainer / Nix
- Python、Node.js、Java、Go、Rust 等语言的结构化清单
- README 中的安装和运行命令
- MCP、LangGraph、OpenAPI 等接口描述
- 可选的 LLM 辅助建造计划

适配层采用“候选计划逐个尝试”的策略：某一个候选失败后，沙箱不会立刻终止，而是继续尝试下一个候选，直到找到可构建、可启动、可交互的运行方式，或所有候选失败。

为了提升速度和稳定性，构建层使用三级镜像策略：

- **一级镜像**：历史成功构建出的 `agent-sandbox-build:*` 镜像，可复用之前构建成功的完整环境。
- **二级镜像**：本地增强基础镜像，例如 `aegisagent-python`、`aegisagent-node`、`aegisagent-java`、`aegisagent-go`、`aegisagent-rust`、`aegisagent-universal`。
- **三级镜像**：公共镜像源或镜像加速源，例如官方 Python、Node、Maven、Go、Rust、Bun、Alpine 等基础镜像。

近期优化重点包括：

- 降低 monorepo 中 docs、examples、CI、e2e、mobile app、benchmark、library module 被误选为主入口的概率。
- 为 Node.js 的 npm、pnpm、yarn、bun 增加镜像源和安装策略适配。
- 为 Java 多模块项目增加更谨慎的 CLI/HTTP 入口识别。
- 为 Go、Rust、Python 等 CLI 项目增强失败分类，例如交互式 TTY、认证缺失、CLI 参数不匹配等。

### 2.5 动态运行阶段

构建成功后，沙箱会在 Docker 容器中启动智能体。运行时会施加安全限制：

- 容器隔离
- 受控网络策略
- 内存限制
- 只读或受限写入策略
- fake env 与 sink 监控
- canary 注入与外传检测

根据智能体接口类型，沙箱会选择不同交互方式：

- HTTP 服务：启动容器后探测端口、OpenAPI、常见聊天接口。
- CLI：通过标准输入或参数模拟用户对话。
- MCP：进行 initialize、list tools、tool call 等协议级交互。
- Browser/网页类应用：通过 HTTP/browser 探测进行交互。

动态运行的完成标准不是“智能体必须回答得像正常聊天产品”，而是沙箱能够完成启动、交互、攻击注入、证据采集和报告生成。

### 2.6 动态攻击阶段

当前动态攻击层采用“内置模板 + LLM 变体 + 沙箱校验”的方式。LLM 可以参与生成自然语言变体，但不能直接执行 shell、写任意路径或使用真实外传 URL。

当前支持和规划中的攻击 step 包括：

- `inject_skill`
- `inject_memory`
- `inject_scheduler`
- `inject_web_page`
- `inject_email`
- `inject_github_issue`
- `inject_mcp_tool_manifest`
- `inject_rag_document`
- `assert_sink_clean`
- `inspect_fake_env`

覆盖的风险类型包括：

- 间接提示注入
- secret exfiltration
- 恶意 URL 跟随
- skill/plugin 注入
- MCP/tool poisoning
- RAG poisoning
- memory poisoning
- scheduler delayed action
- 持久化污染
- 外部服务越权写入

攻击内容会被沙箱改写和约束：

- 真实外传域名替换为 `AGENT_SANDBOX_SINK_URL`
- 真实 secret 替换为 canary
- 写入路径限制在 `.agent_sandbox/`、fake env 数据目录或测试 fixture 目录
- 阻止覆盖项目源码和系统文件

### 2.7 fake environment 阶段

为了避免智能体访问真实外部系统，同时又能观察其行为，AegisAgent 建立了 fake environment。当前 fake env 分为三层：

- **协议级模拟**：模拟 OpenAI-compatible endpoint、webhook sink、HTTP 页面、邮件、GitHub issue、MCP manifest、RAG 文档等。
- **状态机模拟**：记录外部对象读取、页面访问、邮件读取、GitHub issue 访问、状态变化、权限越界、canary 移动和审计事件。
- **本地真实服务替代**：可接入 MailHog/Mailpit、MinIO、Gitea、Playwright 等本地服务，用更接近真实环境的方式承载测试场景。

fake env 的目的不是提供公网，而是在私有网络中模拟外部世界，让智能体“以为自己在访问外部工具”，沙箱则记录它是否读取恶意内容、是否执行不应执行的动作、是否试图外传 canary。

### 2.8 报告生成阶段

测试结束后，后端会生成结构化 JSON 报告，并进一步渲染为面向普通用户的 Markdown 报告。报告内容包括：

- 项目基本信息
- 识别出的语言、框架和接口
- 静态扫描风险
- 使用的 BuildPlan 和构建结果
- 动态攻击计划
- fake env、sink、canary、工具调用等证据
- 风险等级与是否经过动态验证
- 未能验证的原因
- 建议修复方向

前端会直接展示 Markdown 报告，并提供下载能力。

## 3. 核心原理说明

### 3.1 静态能力不等于真实漏洞

很多智能体天然需要读取环境变量、调用工具、访问网络或处理外部内容。如果只看到这些能力就判高危，误报会非常多。

因此 AegisAgent 使用分层证据模型：

- 静态发现危险能力时，先标为 capability risk。
- 如果扫描到接口路径、外部输入路径或工具入口，再提升为 reachable surface。
- 只有动态测试观察到 canary 外传、恶意工具调用、持久化污染、跨重启触发等证据，才标为 observed behavior。

这使得报告更接近真实安全审计：既不忽略潜在危险能力，也不把所有能力都直接当作已利用漏洞。

### 3.2 适配不是 LLM 直接编命令

AegisAgent 的适配层不是让 LLM 随意生成 shell 命令并执行。系统自身会基于结构化规则生成候选计划，LLM 只作为可选辅助：

- 阅读静态扫描结果和部分项目文件
- 给出候选入口和运行方式
- 生成自然语言攻击变体
- 辅助解释报告

所有 LLM 输出都会经过沙箱 schema 校验、路径校验、step 白名单校验和安全改写。LLM 不能突破沙箱边界。

### 3.3 多候选 BuildPlan 提高泛化能力

真实开源智能体仓库经常不是单一入口，而是包含：

- 主应用
- SDK
- examples
- docs demo
- benchmark
- mobile app
- CI/e2e 脚本
- 多语言子项目

如果只选第一个清单文件，很容易误判入口。AegisAgent 会生成多个候选 BuildPlan，并按置信度排序逐个尝试。

候选排序会综合：

- 项目根目录评分
- 是否声明可运行脚本
- 是否存在 HTTP/MCP/CLI 接口
- 是否属于 docs/examples/benchmark/CI 等低优先级路径
- 是否有 README 明确启动命令
- 是否有 lockfile、manifest、源码入口和框架标记

### 3.4 动态攻击依赖证据链

动态攻击不是只看智能体有没有“说错话”，而是看是否出现可验证行为：

- sink 是否收到 canary
- fake env 是否记录恶意 URL 访问
- MCP fake tool 是否被调用
- memory 或 skill 是否被写入并持久化
- scheduler 是否在延迟后触发
- RAG 文档污染是否影响后续回答或工具使用
- GitHub issue/email/web page 中的恶意指令是否被错误执行

这种方式可以把“模型输出风险”转化为“系统行为证据”。

## 4. 当前取得的成果

### 4.1 完成了沙箱主流程闭环

当前项目已经具备从上传到报告的完整链路：

1. 上传智能体压缩包
2. 解包与静态扫描
3. 生成候选 BuildPlan
4. Docker 构建和复用镜像
5. 启动智能体
6. 模拟用户对话
7. 执行动态攻击
8. 记录 fake env 和 sink 证据
9. 生成 JSON 与 Markdown 报告
10. 前端展示和下载报告

### 4.2 多语言适配能力已经形成

目前适配层已覆盖多种常见智能体技术栈：

- Python：LangChain、AutoGen、CrewAI、FastAPI、MCP、普通 CLI
- Node.js：Express、Vite/Next 类 HTTP 应用、MCP、npm/pnpm/yarn/bun
- Java：Maven、Gradle、Spring AI、LangChain4j、Quarkus/Helidon 相关模式
- Go：Go CLI、HTTP 服务
- Rust：Cargo CLI、MCP/agent CLI
- Universal：基于 README、Dockerfile、脚本和通用 Linux 镜像的兜底运行

同时，构建层已经加入本地增强基础镜像和镜像源加速配置，减少重复安装工具链和公共依赖造成的等待。

### 4.3 动态攻击能力显著扩展

动态攻击层已经从简单对话扩展为多入口、多表面的攻击测试：

- skill 注入
- memory poisoning
- scheduler delayed trigger
- MCP tool manifest poisoning
- web page 间接提示注入
- email 间接提示注入
- GitHub issue 间接提示注入
- RAG document poisoning
- canary/sink 外传验证
- fake env 状态检查

这使得沙箱不再只测试“智能体能不能聊天”，而是开始测试智能体在真实应用场景中面对恶意外部内容时是否会失控。

### 4.4 fake env 从单一 sink 扩展为状态化环境

fake environment 已经不只是一个 webhook 接收器，而是具备多种外部服务模拟能力：

- fake OpenAI-compatible endpoint
- fake webhook sink
- fake browser/page
- fake email inbox
- fake GitHub issue/PR
- fake MCP server/tool registry
- fake RAG document store
- fake audit/state/scenario API
- 可选 MailHog/Mailpit、MinIO、Gitea、Playwright 本地真实服务集成

这为后续构建更真实的智能体攻击 benchmark 打下了基础。

### 4.5 报告可读性完成改造

早期报告偏结构化 JSON，普通用户不容易阅读。当前已支持生成面向普通用户的 Markdown 报告，并可在前端直接展示和下载。

报告会明确区分：

- 静态发现
- 动态验证
- 未验证风险
- 证据链
- 风险等级
- 失败原因
- 修复建议

### 4.6 建立了评估框架

项目已经设计并实现了漏洞发现能力评估思路，分为三类样例：

- 真实漏洞集：来自 CVE、GitHub Advisory、OSV、Snyk、论文和博客。
- 合成能力集：覆盖智能体常见攻击能力。
- 负样本集：用于衡量误报控制能力。

评估模式分为：

- `baseline_static`：无 LLM、无动态沙箱，只评估静态规则。
- `baseline_dynamic`：无 LLM，使用默认动态攻击、fake env、canary 和 sink。
- `llm_assisted`：允许 LLM 参与静态审计、构建辅助、攻击计划和报告解释。
- `targeted_oracle`：提供漏洞线索，用于评估已知漏洞复现能力。

评分指标包括：

- build success rate
- dynamic success rate
- static recall
- dynamic recall
- targeted reproduction recall
- false positive rate
- evidence completeness
- report usability

### 4.7 完成多轮适配成功率测试

已经使用多组全新开源智能体样例进行适配层测试。当前观察到：

- 无 LLM 辅助的三轮累计测试：`12/30` 成功，约 `40%`
- 最新一轮全新 10 个样例：`4/10` 成功，成功率 `40%`
- LLM 辅助构建仍存在超时问题，暂时不能作为可靠提升结论

这些测试暴露出真实复杂仓库中的主要难点：

- monorepo 入口识别困难
- docs/example/benchmark/CI/e2e/mobile app 容易被误选
- Node lockfile 与 manifest 不一致
- Java 多模块项目容易误选 library/starter module
- Rust/Go CLI 有交互式初始化、TTY、认证和参数模式差异
- 部分智能体依赖真实 API key 或外部服务登录态

这些问题已经被归类为适配层后续优化重点。

## 5. 当前已知不足

当前版本已经形成完整工程闭环，但仍有几个需要继续增强的方向：

- **适配成功率仍需提高**：全新复杂样例上的成功率约 40%，距离稳定产品化还有差距。
- **LLM 辅助构建需要限流和候选控制**：复杂仓库中 LLM 辅助容易扩大候选数量和构建时间。
- **fake env 仍以协议级和局部真实服务为主**：距离完整真实环境模拟还有距离。
- **动态攻击需要更多真实正样本校准**：尤其是每个攻击分支都需要典型漏洞样例验证。
- **VHDX 和 Docker 空间管理需要工程化**：大量测试会产生镜像和缓存，需要自动清理策略。

## 6. 后续工作建议

后续可以围绕三条线推进：

- **提升适配层成功率**：扩大测试集，按语言和框架统计失败原因，从入口识别、构建缓存、依赖安装、CLI 参数适配上持续优化。
- **深化动态攻击层**：为 skill、memory、scheduler、MCP、RAG、web/email/GitHub 等每个分支建立典型正样本，保证每类风险至少有一个完整证据链。
- **完善评估 benchmark**：持续收集真实智能体漏洞、构造能力型样例和负样本，形成可重复运行的评估集。

## 7. 一句话总结

AegisAgent 5.0 已经从“能运行智能体的沙箱”升级为“能适配、攻击、取证、评估并生成用户可读报告的智能体安全测试平台”。当前核心成果是完成了主流程闭环、多语言适配框架、动态攻击 DSL、fake environment、证据分层和评估体系；下一阶段重点是提高复杂真实仓库上的适配成功率，并用更多带漏洞正样本校准动态攻击效果。
