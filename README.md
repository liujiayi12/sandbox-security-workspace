# Sandbox Security Workspace

Sandbox Security Workspace 是一个面向 Skill 与 Agent 的本地安全沙箱工作区。项目提供独立前端控制台，并接入两个本地后端：Skill 动态沙箱和 Agent 安全分析沙箱，用于对 Skill 包、Agent 项目进行隔离执行、行为观测、风险评估和报告展示。

## 项目定位

本项目适用于以下场景：

- 对待上线的 Skill 进行动态安全检测
- 对 Agent 项目进行隔离运行、静态扫描和风险分析
- 在本地环境中观察文件、进程、网络、工具调用和 LLM 相关行为
- 为安全评审、供应链治理和能力上线审核提供可复核证据

## 核心功能

### Skill 动态沙箱

基于 `clawguard-main` 中的 ProvLoom 动态沙箱能力，支持上传 `SKILL.md`、相关文件或 zip 包，在 Docker 隔离环境中执行并生成检测结果。

主要能力：

- Skill 文件上传、zip 包上传和远程 URL 输入
- 标准检测、隔离检测、快速检测等策略
- 文件、进程、网络、工具调用和 LLM 事件观测
- 风险评分、风险等级、行为证据和执行时间线展示
- 自动生成 Markdown 检测报告，并保留原始 JSON 明细
- 对没有可执行动作定义的 Skill 自动降级为静态能力画像分析
- 批量检测时汇总最高风险结果和每个 Skill 的独立结论
- 运行失败时输出可读的未完成原因，便于区分环境问题和样本风险

### Agent 安全分析

基于 `AegisAgent-main`，支持上传 Agent 项目 zip 包，自动完成结构识别、静态扫描、运行计划发现、Docker 动态执行和报告生成。

主要能力：

- Agent zip 上传
- 自动识别依赖、启动方式和构建线索
- Docker 沙箱动态运行
- 攻击探针与风险证据采集
- 运行事件轮询和最终报告展示

### 独立前端控制台

`sandbox-console` 是独立于 `clawguard-main/web` 的 React/Vite 前端，只保留本工作区需要的两个功能入口。

界面包含：

- 横向导航栏
- 综合安全总览
- Skill 检测工作台
- Agent 分析工作台
- 服务在线状态展示
- Markdown 报告渲染与原始 JSON 展开查看
- 用户友好的上传、策略选择和结果展示流程

## 项目结构

```text
.
├── sandbox-console/              # 独立前端控制台
├── AegisAgent-main/              # Agent 沙箱后端
├── clawguard-main/               # Skill 动态沙箱及相关后端能力
├── start-frontend.ps1            # 启动前端
├── start-aegisagent.ps1          # 启动 Agent 沙箱后端
├── start-skill-dynamic-api.ps1   # 启动 Skill 动态沙箱 API
└── README.md
```

本地运行时还可能生成以下目录，这些目录不需要提交到 Git：

- `runtime-cache/`
- `node_modules/`
- `.venv/`
- `.env`
- 构建产物、日志和本地数据库文件

## 本地运行

### 1. 启动 Agent 沙箱

```powershell
.\start-aegisagent.ps1
```

默认地址：

```text
http://127.0.0.1:8000
```

### 2. 启动 Skill 动态沙箱 API

```powershell
.\start-skill-dynamic-api.ps1
```

默认地址：

```text
http://127.0.0.1:8787
```

当前启动脚本默认设置：

```powershell
$env:PROVLOOM_REBUILD_SANDBOX_IMAGE = "0"
```

这表示启动 API 时不会每次自动重建沙箱镜像。首次运行或镜像变更后，请手动构建镜像，或临时改为 `"1"` 后再启动。

### 3. 启动前端控制台

```powershell
.\start-frontend.ps1
```

默认地址：

```text
http://127.0.0.1:5174
```

## Docker 要求

动态沙箱执行依赖 Docker Desktop。请先确认 Docker 可用：

```powershell
docker run --rm hello-world
```

Skill 动态沙箱镜像可提前构建：

```powershell
cd .\clawguard-main\provloom
$env:DOCKER_BUILDKIT=0
docker build --pull=false -t skill-runtime-sandbox:latest -f docker/sandbox/Dockerfile .
```

如果 Docker Hub 网络不稳定，可以先配置镜像源，或预拉取项目需要的基础镜像。

## LLM 配置

LLM 能力是可选项：

- 不配置 LLM Key：仍可进行基础沙箱检测、规则分析和静态画像分析
- 配置 LLM Key：可启用辅助解释、触发规划和更丰富的风险分析

请勿将真实 API Key 提交到仓库。需要本地配置时，请使用 `.env` 或页面中的临时输入。

## GitHub 提交说明

仓库已配置 `.gitignore`，会排除以下本地文件：

- `.env`
- `.venv`
- `node_modules`
- 构建产物
- Docker 安装器
- 运行缓存
- 本地数据库和日志

## 技术栈

- Frontend: React, Vite, Lucide Icons
- Backend: FastAPI, Node.js/Express, Python
- Sandbox: Docker Desktop
- Runtime: AegisAgent, ProvLoom

## 当前版本

当前版本聚焦于本地双沙箱联调与独立前端展示：

- 已完成独立前端控制台
- 已完成 Skill 动态检测入口
- 已完成 Agent 沙箱分析入口
- 已完成 Docker 动态执行环境适配
- 已支持 Skill Markdown 报告展示和原始 JSON 明细查看
- 已支持无动作 Skill 的静态降级分析
- 后续可继续接入统一登录、任务历史、报告导出和团队权限管理
