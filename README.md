# Sandbox Security Workspace

Sandbox Security Workspace 是一个面向 Skill 与 Agent 的双沙箱安全检测平台。项目提供独立前端控制台，并接入两个本地沙箱后端，用于对 Skill 包和 Agent 项目进行动态执行、行为观测、风险评估与报告展示。

## 项目定位

该项目适用于以下场景：

- 对待上线的 Skill 进行动态安全检测
- 对 Agent 项目进行隔离运行和风险分析
- 在本地环境中观察文件、进程、网络和工具调用行为
- 为安全评审、供应链治理和能力上线审核提供可复核证据

## 核心功能

### Skill 动态检测

基于 `clawguard-main` 中的 ProvLoom 动态沙箱能力，支持上传 `SKILL.md`、相关文件或 zip 包，在 Docker 隔离环境中执行并生成检测结果。

主要能力：

- Skill 文件上传与远程 URL 输入
- 标准检测、隔离检测、快速检测三种策略
- 文件、进程、网络、工具调用行为观测
- 风险评分、行为证据、执行时间线展示
- 可选 LLM 辅助解释

### Agent 安全分析

基于 `AegisAgent-main`，支持上传 Agent 项目 zip 包，自动完成结构识别、静态扫描、运行计划发现、Docker 动态执行和报告生成。

主要能力：

- Agent zip 上传
- 自动识别依赖、启动方式和构建线索
- Docker 沙箱动态运行
- 攻击探针与风险证据采集
- 运行事件轮询与最终报告展示

### 独立前端控制台

`sandbox-console` 是独立于 `clawguard-main/web` 的 React/Vite 前端，仅保留本项目需要的两个功能入口。

界面包含：

- 横向导航栏
- 综合安全总览
- Skill 检测工作台
- Agent 分析工作台
- 服务在线状态展示
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

如果 Docker Hub 网络不稳定，可以使用国内镜像源预拉取基础镜像。

Skill 动态沙箱镜像可提前构建：

```powershell
cd .\clawguard-main\provloom
$env:DOCKER_BUILDKIT=0
docker build --pull=false -t skill-runtime-sandbox:latest -f docker/sandbox/Dockerfile .
```

## LLM 配置

LLM 能力为可选项。

- 不配置 LLM Key：仍可进行基础沙箱检测和规则分析
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
- 后续可继续接入统一登录、任务历史、报告导出和团队权限管理
