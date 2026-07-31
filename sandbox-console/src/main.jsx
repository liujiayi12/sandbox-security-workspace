import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  Archive,
  BarChart3,
  Bot,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  Clock3,
  FileArchive,
  FileCode2,
  FileSearch,
  Gauge,
  Info,
  KeyRound,
  Layers3,
  LayoutDashboard,
  ListChecks,
  Lock,
  Network,
  Play,
  Radar,
  RefreshCcw,
  Route,
  ScanLine,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Sparkles,
  TerminalSquare,
  UploadCloud,
} from "lucide-react";
import "./styles.css";

const SKILL_API = "/skill-api";
const AGENT_API = "/agent-api";

const navItems = [
  { id: "overview", label: "安全总览", icon: LayoutDashboard },
  { id: "skill", label: "Skill 检测", icon: Radar },
  { id: "agent", label: "Agent 分析", icon: Bot },
  { id: "admin", label: "管理后台", icon: KeyRound, adminOnly: true },
];

const skillPresets = {
  balanced: {
    label: "标准检测",
    description: "适合日常提交，平衡速度和证据完整度。",
    timeoutSeconds: 180,
    networkPolicy: "default",
    analysisMode: "rule_plus_epg",
    prompt: "请按 SKILL.md 的主要说明执行一次核心工作流，记录文件、进程、网络和工具调用证据。",
  },
  locked: {
    label: "隔离检测",
    description: "禁用外部网络，适合检查本地行为和敏感文件访问。",
    timeoutSeconds: 120,
    networkPolicy: "disabled",
    analysisMode: "rule_plus_epg",
    prompt: "请在禁用外部网络的沙箱中执行 Skill 的核心流程，重点观察文件、进程和工具调用行为。",
  },
  quick: {
    label: "快速检测",
    description: "更短运行时间，适合先做一次轻量验证。",
    timeoutSeconds: 60,
    networkPolicy: "default",
    analysisMode: "rule_only",
    prompt: "请快速执行 Skill 的主要入口，返回可观察到的安全行为证据。",
  },
};

const agentPresets = {
  standard: {
    label: "标准沙箱",
    description: "自动识别运行计划，使用缓存，适合大多数 Agent。",
    runtimeNetwork: "auto",
    buildMode: "auto",
    cachePolicy: "use",
  },
  strict: {
    label: "严格沙箱",
    description: "收紧运行网络和构建策略，适合不可信样本。",
    runtimeNetwork: "none",
    buildMode: "strict",
    cachePolicy: "use",
  },
  rebuild: {
    label: "重新构建",
    description: "忽略旧缓存，适合依赖变化后的复测。",
    runtimeNetwork: "auto",
    buildMode: "auto",
    cachePolicy: "rebuild",
  },
};

const defaultRuntimeEnv = {
  OPENAI_API_KEY: "",
  OPENAI_BASE_URL: "https://api.openai.com/v1",
  MODEL_NAME: "gpt-4o-mini",
};

const capabilityCards = [
  {
    icon: ScanLine,
    title: "运行期行为观测",
    text: "跟踪文件访问、命令执行、网络连接和工具调用，帮助判断能力描述与真实行为是否一致。",
  },
  {
    icon: ShieldAlert,
    title: "风险分层呈现",
    text: "将可疑行为映射为风险评分、等级和复核建议，适合上线前评审与持续治理。",
  },
  {
    icon: FileSearch,
    title: "证据驱动报告",
    text: "保留时间线、事件摘要和检测明细，方便团队复盘、留档和二次分析。",
  },
];

const workflowSteps = [
  { title: "提交对象", text: "上传 Skill 文件、Skill 压缩包或 Agent 项目压缩包。" },
  { title: "选择策略", text: "按可信度选择标准、隔离、严格或重建策略。" },
  { title: "沙箱执行", text: "检测引擎在隔离环境中运行目标并采集关键行为。" },
  { title: "复核报告", text: "查看风险等级、证据链和最终检测报告。" },
];

const skillBriefItems = [
  { icon: FileCode2, title: "适配对象", text: "技能说明文件、技能目录压缩包、远程 Skill 链接。" },
  { icon: Network, title: "观察重点", text: "文件读写、外部请求、命令执行、工具调用路径。" },
  { icon: ClipboardCheck, title: "输出结果", text: "风险评分、命中行为、证据时间线和检测明细。" },
];

const agentBriefItems = [
  { icon: FileArchive, title: "适配对象", text: "完整 Agent 项目压缩包，包含依赖与启动入口。" },
  { icon: Layers3, title: "沙箱过程", text: "结构识别、依赖构建、隔离运行、事件采集。" },
  { icon: BarChart3, title: "输出结果", text: "任务状态、阶段事件、风险等级和最终报告。" },
];

const skillEvidenceItems = ["风险评分", "可疑行为", "执行时间线", "检测明细"];
const agentEvidenceItems = ["任务阶段", "事件流水", "安全报告", "运行配置"];

function cx(...values) {
  return values.filter(Boolean).join(" ");
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "--";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

async function readAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const value = String(reader.result || "");
      resolve(value.includes(",") ? value.split(",").pop() : value);
    };
    reader.onerror = () => reject(new Error(`读取文件失败：${file.name}`));
    reader.readAsDataURL(file);
  });
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { message: text };
  }
  if (!response.ok) {
    const error = new Error(data?.message || data?.detail || `请求失败：${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

function formatSkillError(error) {
  const raw = String(error?.message || error?.data?.message || "").trim();
  const lower = raw.toLowerCase();
  const looksGarbled = /锟絴閿焲缁媩鐎箌忙|氓|盲|脗|脨|脩/.test(raw);

  if (error?.status === 401) {
    return "登录状态已失效，请重新登录后再试。";
  }
  if (lower.includes("upload") || lower.includes("downloadable url") || lower.includes("no files")) {
    return "请先选择要检测的 Skill 文件或压缩包，或填写可直接下载的文件链接。";
  }
  if (lower.includes("does not define executable actions") || lower.includes("skill-actions")) {
    return "已找到 SKILL.md。该 Skill 没有显式 skill-actions，需要启用 LLM 辅助触发与运行时适配，并填写模型密钥后重试。";
  }
  if (lower.includes("llm_config.api_key") || lower.includes("api_key") || lower.includes("api key")) {
    return "动态沙箱的 LLM 运行时需要模型密钥。请在 Skill 高级设置中填写智能分析密钥后重试。";
  }
  if (lower.includes("html page") || lower.includes("raw skill markdown")) {
    return "上传的 SKILL.md 看起来是网页 HTML，不是原始 Skill Markdown。请从 GitHub/网页中下载 Raw 原始文件，或上传完整 Skill 目录压缩包。";
  }
  if (lower.includes("元数据") || lower.includes("_meta.json") || lower.includes("skill.json")) {
    return "上传的压缩包只包含 Skill 元数据，没有包含 SKILL.md 正文。请上传完整 Skill 目录压缩包，或直接上传 SKILL.md 文件。";
  }
  if (lower.includes("skill.md")) {
    return "未在上传内容中找到 SKILL.md。请上传包含 SKILL.md 的完整技能目录压缩包，或直接上传 SKILL.md 文件。";
  }
  if (lower.includes("zip") || lower.includes("archive")) {
    return "上传的压缩包无法识别。请确认文件未损坏，并包含完整的 Skill 目录。";
  }
  if (looksGarbled) {
    return "检测任务未能启动。请确认上传的是有效 Skill 包后重试。";
  }
  return raw || "动态检测失败，请稍后重试。";
}

function useServiceStatus() {
  const [status, setStatus] = useState({
    skill: { state: "checking", label: "检测中" },
    agent: { state: "checking", label: "检测中" },
    capacity: null,
  });

  const refresh = async () => {
    const next = {
      skill: { state: "offline", label: "未启动" },
      agent: { state: "offline", label: "未启动" },
      capacity: null,
    };

    try {
      await fetchJson(`${SKILL_API}/api/health`);
      next.skill = { state: "online", label: "在线" };
      const capacity = await fetchJson(`${SKILL_API}/api/skill/dynamic-sandbox/capacity`);
      next.capacity = capacity?.capacity || null;
    } catch {
      next.skill = { state: "offline", label: "未连接" };
    }

    try {
      const response = await fetch(`${AGENT_API}/docs`);
      if (!response.ok) throw new Error("offline");
      next.agent = { state: "online", label: "在线" };
    } catch {
      next.agent = { state: "offline", label: "未连接" };
    }

    setStatus(next);
  };

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 20000);
    return () => window.clearInterval(timer);
  }, []);

  return { status, refresh };
}

function StatusPill({ state, label }) {
  return (
    <span className={cx("status-pill", state)}>
      <span />
      {label}
    </span>
  );
}

function PanelHeader({ icon: Icon, title, subtitle, action }) {
  return (
    <div className="panel-header">
      <div className="panel-title">
        <div className="panel-icon">
          <Icon size={20} />
        </div>
        <div>
          <h2>{title}</h2>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
      </div>
      {action}
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, hint, tone = "blue" }) {
  return (
    <article className={cx("metric-card", tone)}>
      <div className="metric-icon">
        <Icon size={22} />
      </div>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
        <span>{hint}</span>
      </div>
    </article>
  );
}

function Stepper({ steps, current }) {
  return (
    <div className="stepper">
      {steps.map((step, index) => (
        <div className={cx("step", index <= current && "active")} key={step}>
          <span>{index + 1}</span>
          <strong>{step}</strong>
        </div>
      ))}
    </div>
  );
}

function PresetSelector({ presets, value, onChange }) {
  return (
    <div className="preset-grid">
      {Object.entries(presets).map(([key, preset]) => (
        <button className={cx("preset-card", value === key && "selected")} key={key} type="button" onClick={() => onChange(key)}>
          <CheckCircle2 size={18} />
          <strong>{preset.label}</strong>
          <span>{preset.description}</span>
        </button>
      ))}
    </div>
  );
}

function FileDrop({ accept, multiple = true, files, onFiles, title, description, icon: Icon }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);

  const append = (list) => {
    const incoming = Array.from(list || []);
    if (!incoming.length) return;
    onFiles(multiple ? [...files, ...incoming] : incoming.slice(0, 1));
    if (inputRef.current) {
      inputRef.current.value = "";
    }
  };

  return (
    <div
      className={cx("file-drop", dragging && "dragging")}
      onDragOver={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        append(event.dataTransfer.files);
      }}
    >
      <input ref={inputRef} type="file" multiple={multiple} accept={accept} onChange={(event) => append(event.target.files)} />
      <div className="drop-icon">
        <Icon size={26} />
      </div>
      <div>
        <strong>{title}</strong>
        <p>{description}</p>
      </div>
      <button type="button" onClick={() => inputRef.current?.click()}>
        <UploadCloud size={17} />
        选择文件
      </button>
    </div>
  );
}

function FileList({ files, onClear }) {
  if (!files.length) return <div className="empty-line">尚未选择文件。</div>;
  return (
    <div className="file-list">
      {files.map((file, index) => (
        <div className="file-row" key={`${file.name}-${file.size}-${index}`}>
          <FileCode2 size={16} />
          <span>{file.webkitRelativePath || file.name}</span>
          <em>{formatBytes(file.size)}</em>
        </div>
      ))}
      <button className="ghost-button compact" type="button" onClick={onClear}>
        清空文件
      </button>
    </div>
  );
}

function Field({ label, children, hint }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint ? <em>{hint}</em> : null}
    </label>
  );
}

function AdvancedBox({ title = "高级设置", children }) {
  return (
    <details className="advanced-box">
      <summary>
        <Settings2 size={17} />
        {title}
      </summary>
      <div>{children}</div>
    </details>
  );
}

function EmptyState({ icon: Icon, title, text }) {
  return (
    <div className="empty-state">
      <Icon size={34} />
      <strong>{title}</strong>
      <p>{text}</p>
    </div>
  );
}

function Timeline({ items }) {
  const normalized = Array.isArray(items) ? items.slice(0, 12) : [];
  if (!normalized.length) return <div className="timeline empty">暂无运行事件。</div>;

  return (
    <div className="timeline">
      {normalized.map((item, index) => (
        <div className="timeline-item" key={`${item.timestamp || item.time || index}-${index}`}>
          <span className="timeline-dot" />
          <div>
            <strong>{item.stage || item.action || item.type || `事件 ${index + 1}`}</strong>
            <p>{item.message || item.summary || item.description || JSON.stringify(item).slice(0, 180)}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

function JsonPreview({ data }) {
  return (
    <details className="json-preview">
      <summary>检测明细</summary>
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </details>
  );
}

function ExpandableDetail({ title, actionLabel = "放大查看", children, className }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <div className={cx("expandable-detail", className)}>
        <div className="expandable-detail-head">
          <strong>{title}</strong>
          <button className="ghost-button compact" type="button" onClick={() => setOpen(true)}>
            <ScanLine size={15} />
            {actionLabel}
          </button>
        </div>
        <div className="expandable-detail-body">{children}</div>
      </div>
      {open ? (
        <div className="detail-modal" role="dialog" aria-modal="true">
          <div className="detail-modal-panel">
            <div className="detail-modal-head">
              <strong>{title}</strong>
              <button className="icon-button" type="button" onClick={() => setOpen(false)} title="关闭">
                ×
              </button>
            </div>
            <div className="detail-modal-body">{children}</div>
          </div>
        </div>
      ) : null}
    </>
  );
}

function ReadinessPanel({ serviceStatus }) {
  const items = [
    { label: "Skill 动态检测服务", status: serviceStatus.skill },
    { label: "Agent 沙箱服务", status: serviceStatus.agent },
    {
      label: "Skill 并发容量",
      status: serviceStatus.capacity ? { state: "online", label: `${serviceStatus.capacity.available}/${serviceStatus.capacity.limit}` } : { state: "checking", label: "待同步" },
    },
  ];

  return (
    <article className="insight-card readiness-card">
      <PanelHeader icon={ListChecks} title="运行就绪" subtitle="服务可用性会自动刷新，提交前建议确认目标服务在线。" />
      <div className="readiness-list">
        {items.map((item) => (
          <div className="readiness-row" key={item.label}>
            <span>{item.label}</span>
            <StatusPill state={item.status.state} label={item.status.label} />
          </div>
        ))}
      </div>
    </article>
  );
}

function WorkflowPanel() {
  return (
    <article className="insight-card workflow-card">
      <PanelHeader icon={Route} title="检测流程" subtitle="从上传到报告的关键步骤保持可追踪，便于团队协作复核。" />
      <div className="workflow-list">
        {workflowSteps.map((step, index) => (
          <div className="workflow-row" key={step.title}>
            <span>{String(index + 1).padStart(2, "0")}</span>
            <div>
              <strong>{step.title}</strong>
              <p>{step.text}</p>
            </div>
          </div>
        ))}
      </div>
    </article>
  );
}

function CapabilityMatrix() {
  return (
    <article className="insight-card wide-card">
      <PanelHeader icon={ShieldCheck} title="核心能力" subtitle="围绕沙箱执行证据组织页面，展示任务状态和可解释的安全结论。" />
      <div className="capability-grid">
        {capabilityCards.map((item) => {
          const Icon = item.icon;
          return (
            <div className="capability-card" key={item.title}>
              <Icon size={22} />
              <strong>{item.title}</strong>
              <p>{item.text}</p>
            </div>
          );
        })}
      </div>
    </article>
  );
}

function TaskBrief({ type }) {
  const items = type === "agent" ? agentBriefItems : skillBriefItems;
  return (
    <div className="task-brief">
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <article className="brief-card" key={item.title}>
            <Icon size={19} />
            <div>
              <strong>{item.title}</strong>
              <p>{item.text}</p>
            </div>
          </article>
        );
      })}
    </div>
  );
}

function EvidencePreview({ title, items }) {
  return (
    <div className="evidence-preview">
      <div className="evidence-hero">
        <div>
          <ShieldQuestion size={32} />
          <strong>{title}</strong>
          <p>提交任务后，系统会把沙箱执行结果整理成适合复核的安全视图。</p>
        </div>
      </div>
      <div className="evidence-grid">
        {items.map((item) => (
          <div className="evidence-chip" key={item}>
            <CheckCircle2 size={16} />
            {item}
          </div>
        ))}
      </div>
    </div>
  );
}

function OverviewPage({ serviceStatus, onNavigate, onRefresh }) {
  const onlineCount = [serviceStatus.skill, serviceStatus.agent].filter((item) => item.state === "online").length;

  return (
    <main className="page-grid overview-grid">
      <section className="hero-panel">
        <div className="hero-copy">
          <div className="eyebrow">
            <Sparkles size={16} />
            安全检测工作台
          </div>
          <h1>用沙箱验证 Skill 与 Agent 的真实行为</h1>
          <p>
            面向上线评审、安全分析和供应链治理。上传目标文件后，系统会展示运行阶段、风险评分、行为证据和检测报告。
          </p>
          <div className="hero-actions">
            <button className="primary-button" type="button" onClick={() => onNavigate("skill")}>
              <Radar size={18} />
              检测 Skill
            </button>
            <button className="secondary-button" type="button" onClick={() => onNavigate("agent")}>
              <Bot size={18} />
              分析 Agent
            </button>
          </div>
          <div className="hero-stats">
            <div>
              <strong>2</strong>
              <span>检测入口</span>
            </div>
            <div>
              <strong>4</strong>
              <span>证据视图</span>
            </div>
            <div>
              <strong>实时</strong>
              <span>服务状态</span>
            </div>
          </div>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <div className="data-rail rail-one">
            <span />
            <span />
            <span />
          </div>
          <div className="data-rail rail-two">
            <span />
            <span />
            <span />
          </div>
          <div className="scan-ring" />
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="core-node">
            <ShieldCheck size={42} />
          </div>
          <div className="signal-card card-a">
            <Route size={17} />
            证据链
          </div>
          <div className="signal-card card-b">
            <Network size={17} />
            网络行为
          </div>
          <div className="signal-card card-c">
            <TerminalSquare size={17} />
            运行轨迹
          </div>
        </div>
      </section>

      <section className="metrics-row">
        <MetricCard icon={Gauge} label="检测服务" value={`${onlineCount}/2`} hint="自动检查服务状态" />
        <MetricCard icon={ClipboardCheck} label="报告输出" value="3类" hint="风险评分、行为证据、检测报告" tone="cyan" />
        <MetricCard icon={Archive} label="检测对象" value="Skill / Agent" hint="支持文件与压缩包上传" tone="indigo" />
      </section>

      <section className="service-map">
        <PanelHeader
          icon={ShieldCheck}
          title="开始检测"
          subtitle="选择检测对象后，按页面引导完成上传、策略选择和报告查看。"
          action={<button className="icon-button" type="button" onClick={onRefresh} title="刷新状态"><RefreshCcw size={17} /></button>}
        />
        <div className="feature-cards">
          <FeatureCard
            icon={Radar}
            title="Skill 动态检测"
            text="对 Skill 文件或技能压缩包进行隔离执行，输出风险画像、行为证据和时间线。"
            status={serviceStatus.skill}
            onClick={() => onNavigate("skill")}
          />
          <FeatureCard
            icon={Bot}
            title="Agent 安全分析"
            text="上传 Agent 项目压缩包后自动识别结构、生成运行计划，并在隔离环境中产出检测报告。"
            status={serviceStatus.agent}
            onClick={() => onNavigate("agent")}
          />
        </div>
      </section>

      <section className="insight-grid">
        <CapabilityMatrix />
        <WorkflowPanel />
        <ReadinessPanel serviceStatus={serviceStatus} />
      </section>
    </main>
  );
}

function FeatureCard({ icon: Icon, title, text, status, onClick }) {
  return (
    <button className="feature-card" type="button" onClick={onClick}>
      <div className="feature-icon"><Icon size={24} /></div>
      <strong>{title}</strong>
      <p>{text}</p>
      <StatusPill state={status.state} label={status.label} />
    </button>
  );
}

function AuthPage({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [phone, setPhone] = useState("");
  const [inviteCode, setInviteCode] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const isRegister = mode === "register";

  const submit = async (event) => {
    event.preventDefault();
    setMessage("");
    setSubmitting(true);
    try {
      const data = await fetchJson(`${SKILL_API}/api/auth/${isRegister ? "register" : "login"}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(isRegister ? { username, password, phone, inviteCode } : { username, password }),
      });
      onAuthenticated(data);
      setPassword("");
    } catch (err) {
      setMessage(err.message || (isRegister ? "注册失败，请检查填写信息。" : "登录失败，请检查账号信息。"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-shell">
      <section className="auth-visual-panel">
        <div className="auth-grid-light" />
        <div className="auth-orbit">
          <ShieldCheck size={44} />
        </div>
        <div className="auth-signal signal-one">Skill 动态检测</div>
        <div className="auth-signal signal-two">Agent 沙箱分析</div>
        <div className="auth-signal signal-three">风险证据报告</div>
      </section>

      <section className="auth-card">
        <div className="brand auth-brand">
          <div className="brand-mark">
            <ShieldCheck size={25} />
          </div>
          <div>
            <strong>ASGuard</strong>
            <span>Skill 与 Agent 安全检测</span>
          </div>
        </div>

        <div className="auth-heading">
          <div className="eyebrow">
            <KeyRound size={16} />
            {isRegister ? "创建账号" : "安全登录"}
          </div>
          <h1>{isRegister ? "注册后进入检测平台" : "登录后进入检测平台"}</h1>
          <p>平台包含动态 Skill 检测和 Agent 沙箱分析，登录后即可提交检测任务并查看安全报告。</p>
        </div>

        <div className="auth-tabs">
          <button className={cx(mode === "login" && "active")} type="button" onClick={() => setMode("login")}>
            登录
          </button>
          <button className={cx(mode === "register" && "active")} type="button" onClick={() => setMode("register")}>
            注册
          </button>
        </div>

        <form className="auth-form" onSubmit={submit}>
          <Field label="账号">
            <input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="请输入账号" autoComplete="username" />
          </Field>
          <Field label="密码">
            <input value={password} onChange={(event) => setPassword(event.target.value)} placeholder="请输入密码" type="password" autoComplete={isRegister ? "new-password" : "current-password"} />
          </Field>
          {isRegister ? (
            <>
              <Field label="手机号">
                <input value={phone} onChange={(event) => setPhone(event.target.value)} placeholder="请输入手机号" />
              </Field>
              <Field label="邀请码">
                <input value={inviteCode} onChange={(event) => setInviteCode(event.target.value)} placeholder="请输入邀请码" />
              </Field>
            </>
          ) : null}
          <button className="primary-button wide" disabled={!username.trim() || !password || (isRegister && (!phone.trim() || !inviteCode.trim())) || submitting} type="submit">
            {submitting ? <RefreshCcw className="spin" size={18} /> : <KeyRound size={18} />}
            {submitting ? "处理中" : isRegister ? "注册并进入" : "登录平台"}
          </button>
          {message ? <div className="error-banner"><AlertTriangle size={18} />{message}</div> : null}
        </form>
      </section>
    </main>
  );
}

function SkillPanel({ serviceStatus, onRefresh, token, onAuthExpired }) {
  const [files, setFiles] = useState([]);
  const [sourceUrl, setSourceUrl] = useState("");
  const [preset, setPreset] = useState("balanced");
  const [customPrompt, setCustomPrompt] = useState("");
  const [llmEnabled, setLlmEnabled] = useState(true);
  const [llmApiKey, setLlmApiKey] = useState("");
  const [llmModel, setLlmModel] = useState("deepseek-ai/DeepSeek-V3");
  const [llmBaseUrl, setLlmBaseUrl] = useState("https://api.siliconflow.cn/v1");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const selected = skillPresets[preset];
  const hasTarget = files.length > 0 || sourceUrl.trim();
  const canRun = Boolean(token && hasTarget);
  const updateFiles = (nextFiles) => {
    setFiles(nextFiles);
    setError("");
    setResult(null);
  };
  const updateSourceUrl = (value) => {
    setSourceUrl(value);
    setError("");
    setResult(null);
  };

  const runScan = async () => {
    setError("");
    setResult(null);
    if (!files.length && !sourceUrl.trim()) {
      setError("请先选择要检测的 Skill 文件或压缩包，或填写可直接下载的文件链接。");
      return;
    }
    setRunning(true);
    try {
      const uploadFiles = await Promise.all(
        files.map(async (file) => ({
          name: file.name,
          relativePath: file.webkitRelativePath || file.name,
          contentBase64: await readAsBase64(file),
        })),
      );
      if (!uploadFiles.length && !sourceUrl.trim()) {
        setError("本次检测没有读取到文件内容。请重新点击“选择文件”，确认文件名显示后再提交。");
        return;
      }

      const payload = {
        files: uploadFiles,
        sourceUrl: sourceUrl.trim(),
        inputPayload: { prompt: customPrompt.trim() || selected.prompt },
        timeoutSeconds: selected.timeoutSeconds,
        networkPolicy: selected.networkPolicy,
        analysisMode: selected.analysisMode,
        llmConfig: {
          enabled: llmEnabled,
          provider: inferSkillLlmProvider(llmBaseUrl, llmModel),
          base_url: normalizeSkillLlmBaseUrl(llmBaseUrl, llmModel),
          model: llmModel.trim(),
          ...(llmApiKey.trim() ? { api_key: llmApiKey.trim() } : {}),
        },
      };

      const data = await fetchJson(`${SKILL_API}/api/skill/dynamic-sandbox`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token.trim() ? { Authorization: `Bearer ${token.trim()}` } : {}),
        },
        body: JSON.stringify(payload),
      });
      setResult(data.result || data);
      onRefresh();
    } catch (err) {
      if (err.status === 401) {
        onAuthExpired();
      }
      setError(formatSkillError(err));
    } finally {
      setRunning(false);
    }
  };

  const riskScore = Number(result?.riskScore ?? 0);
  const behaviors = Array.isArray(result?.detectedBehaviors) ? result.detectedBehaviors : [];
  const timeline = Array.isArray(result?.evidenceTimeline) ? result.evidenceTimeline : [];
  const currentStep = result ? 2 : hasTarget ? 1 : 0;

  return (
    <main className="page-grid task-layout">
      <section className="task-panel">
        <PanelHeader
          icon={Radar}
          title="动态 Skill 检测"
          subtitle="适合检测 Codex Skill、插件技能包或疑似可执行能力描述。"
          action={<StatusPill state={serviceStatus.skill.state} label={serviceStatus.skill.label} />}
        />
        <Stepper steps={["上传目标", "选择策略", "查看结果"]} current={currentStep} />
        <TaskBrief type="skill" />

        <div className="task-grid">
          <div className="task-main">
            <FileDrop
              accept=".zip,.md,.txt,.json,.yaml,.yml"
              files={files}
              onFiles={updateFiles}
              icon={FileCode2}
              title="上传 Skill 文件或压缩包"
              description="支持上传单个 Skill，也支持上传包含多个 Skill 的合集压缩包。"
            />
            <FileList files={files} onClear={() => updateFiles([])} />
            <Field label="或填写文件链接" hint="支持可直接读取的 Skill 文件或压缩包链接。">
              <input value={sourceUrl} onChange={(event) => updateSourceUrl(event.target.value)} placeholder="https://example.com/skill-package" />
            </Field>
            <div className="submit-hint">
              {files.length ? `本次将提交 ${files.length} 个文件：${files.map((file) => file.webkitRelativePath || file.name).slice(0, 3).join("、")}${files.length > 3 ? " 等" : ""}` : "尚未选择本地文件。"}
            </div>
            <Field label="检测策略">
              <PresetSelector presets={skillPresets} value={preset} onChange={setPreset} />
            </Field>
            <AdvancedBox>
              <Field label="自定义执行意图" hint="留空时使用所选策略的默认意图。">
                <textarea value={customPrompt} onChange={(event) => setCustomPrompt(event.target.value)} placeholder={selected.prompt} />
              </Field>
              <Field label="智能分析模型">
                <input value={llmModel} onChange={(event) => setLlmModel(event.target.value)} />
              </Field>
              <Field label="模型服务地址" hint="DeepSeek 官方 key 使用 https://api.deepseek.com；硅基流动 key 使用 https://api.siliconflow.cn/v1。">
                <input value={llmBaseUrl} onChange={(event) => setLlmBaseUrl(event.target.value)} placeholder="https://api.deepseek.com" />
              </Field>
              <div className="model-provider-actions">
                <button type="button" className="ghost-button compact" onClick={() => {
                  setLlmBaseUrl("https://api.deepseek.com");
                  setLlmModel("deepseek-chat");
                }}>
                  DeepSeek 官方
                </button>
                <button type="button" className="ghost-button compact" onClick={() => {
                  setLlmBaseUrl("https://api.siliconflow.cn/v1");
                  setLlmModel("deepseek-ai/DeepSeek-V3");
                }}>
                  硅基流动
                </button>
              </div>
              <label className="check-row">
                <input type="checkbox" checked={llmEnabled} onChange={(event) => setLlmEnabled(event.target.checked)} />
                <span>启用 LLM 辅助触发与运行时适配</span>
              </label>
              <Field label="智能分析密钥">
                <input type="password" value={llmApiKey} onChange={(event) => setLlmApiKey(event.target.value)} placeholder="instruction-only Skill 需要填写模型密钥" />
              </Field>
            </AdvancedBox>
            <button className="primary-button wide" disabled={!canRun || running} type="button" onClick={runScan}>
              {running ? <RefreshCcw className="spin" size={18} /> : <Play size={18} />}
              {running ? "正在检测" : "开始检测"}
            </button>
            {error ? <div className="error-banner"><AlertTriangle size={18} />{error}</div> : null}
          </div>

          <ResultAside
            title="Skill 风险画像"
            emptyIcon={ShieldQuestion}
            emptyTitle="等待检测结果"
            emptyText="完成一次检测后，这里会展示风险评分、行为证据和执行时间线。"
            result={result}
            fallback={<EvidencePreview title="检测完成后你会看到" items={skillEvidenceItems} />}
          >
            <SkillRiskDashboard result={result} />
          </ResultAside>
        </div>
      </section>
    </main>
  );
}

function normalizeSkillLlmBaseUrl(baseUrl = "", model = "") {
  const rawBaseUrl = String(baseUrl || "").trim();
  const rawModel = String(model || "").trim().toLowerCase();
  if (rawBaseUrl) return rawBaseUrl.replace(/\/+$/, "");
  if (rawModel === "deepseek-chat" || rawModel.startsWith("deepseek-reasoner")) {
    return "https://api.deepseek.com";
  }
  return "https://api.siliconflow.cn/v1";
}

function inferSkillLlmProvider(baseUrl = "", model = "") {
  const normalizedBaseUrl = normalizeSkillLlmBaseUrl(baseUrl, model).toLowerCase();
  if (normalizedBaseUrl.includes("deepseek.com")) return "deepseek";
  if (normalizedBaseUrl.includes("siliconflow")) return "siliconflow";
  return "openai-compatible";
}

function AgentPanel({ serviceStatus, onRefresh }) {
  const [file, setFile] = useState(null);
  const [preset, setPreset] = useState("standard");
  const [runtimeEnv, setRuntimeEnv] = useState(defaultRuntimeEnv);
  const [providers, setProviders] = useState([]);
  const [allowInstallScripts, setAllowInstallScripts] = useState(true);
  const [deleteImage, setDeleteImage] = useState(false);
  const [running, setRunning] = useState(false);
  const [run, setRun] = useState(null);
  const [events, setEvents] = useState([]);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");

  const selected = agentPresets[preset];

  const pollRun = async (runId) => {
    for (let index = 0; index < 240; index += 1) {
      const summary = await fetchJson(`${AGENT_API}/api/runs/${runId}`);
      setRun(summary);
      try {
        const eventData = await fetchJson(`${AGENT_API}/api/runs/${runId}/events`);
        setEvents(eventData.events || []);
      } catch {
        // Summary polling is enough to keep the page alive.
      }
      if (["completed", "failed"].includes(summary.status)) break;
      await new Promise((resolve) => window.setTimeout(resolve, 2500));
    }

    try {
      const data = await fetchJson(`${AGENT_API}/api/runs/${runId}/report`);
      setReport(data);
    } catch {
      setReport(null);
    }
  };

  const runAgent = async () => {
    if (!file) return;
    setError("");
    setRun(null);
    setEvents([]);
    setReport(null);
    setRunning(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("providers", JSON.stringify(providers.filter((item) => item.api_key)));
      formData.append("runtime_env", JSON.stringify(runtimeEnv));
      formData.append("runtime_network", selected.runtimeNetwork);
      formData.append("build_mode", selected.buildMode);
      formData.append("cache_policy", selected.cachePolicy);
      formData.append("allow_install_scripts", String(allowInstallScripts));
      formData.append("delete_build_image_after_run", String(deleteImage));
      const created = await fetchJson(`${AGENT_API}/api/runs`, { method: "POST", body: formData });
      setRun(created);
      onRefresh();
      await pollRun(created.id || created.run_id);
    } catch (err) {
      setError(err.message || "Agent 沙箱运行失败");
    } finally {
      setRunning(false);
    }
  };

  const currentStep = run || report ? 2 : file ? 1 : 0;
  const latestStage = run?.stage || events.at(-1)?.stage || "待提交";
  const riskLevel = report?.risk_level || report?.riskLevel || run?.risk_level || "--";

  return (
    <main className="page-grid task-layout">
      <section className="task-panel">
        <PanelHeader
          icon={Bot}
          title="Agent 沙箱"
          subtitle="适合上传 Agent 项目压缩包，自动完成结构识别、构建和隔离运行验证。"
          action={<StatusPill state={serviceStatus.agent.state} label={serviceStatus.agent.label} />}
        />
        <Stepper steps={["上传 Agent", "选择沙箱", "查看报告"]} current={currentStep} />

        <div className="task-grid">
          <div className="task-main">
            <FileDrop
              accept=".zip"
              multiple={false}
              files={file ? [file] : []}
              onFiles={(list) => setFile(list[0] || null)}
              icon={FileArchive}
              title="上传 Agent 项目压缩包"
              description="请上传完整项目 zip，系统会自动识别依赖、启动方式和运行风险。"
            />
            <FileList files={file ? [file] : []} onClear={() => setFile(null)} />
            <Field label="沙箱策略">
              <PresetSelector presets={agentPresets} value={preset} onChange={setPreset} />
            </Field>
            <AdvancedBox>
              <div className="form-grid two">
                <Field label="OpenAI API Key">
                  <input
                    type="password"
                    value={runtimeEnv.OPENAI_API_KEY}
                    onChange={(event) => setRuntimeEnv({ ...runtimeEnv, OPENAI_API_KEY: event.target.value })}
                    placeholder="可选，用于被测 Agent 运行时"
                  />
                </Field>
                <Field label="模型名称">
                  <input value={runtimeEnv.MODEL_NAME} onChange={(event) => setRuntimeEnv({ ...runtimeEnv, MODEL_NAME: event.target.value })} />
                </Field>
              </div>
              <Field label="OpenAI Base URL">
                <input value={runtimeEnv.OPENAI_BASE_URL} onChange={(event) => setRuntimeEnv({ ...runtimeEnv, OPENAI_BASE_URL: event.target.value })} />
              </Field>
              <label className="check-row">
                <input type="checkbox" checked={allowInstallScripts} onChange={(event) => setAllowInstallScripts(event.target.checked)} />
                <span>允许依赖安装脚本</span>
              </label>
              <label className="check-row">
                <input type="checkbox" checked={deleteImage} onChange={(event) => setDeleteImage(event.target.checked)} />
                <span>运行后删除本次构建镜像</span>
              </label>
            </AdvancedBox>
            <button className="primary-button wide" disabled={!file || running} type="button" onClick={runAgent}>
              {running ? <RefreshCcw className="spin" size={18} /> : <Play size={18} />}
              {running ? "沙箱运行中" : "提交沙箱任务"}
            </button>
            {error ? <div className="error-banner"><AlertTriangle size={18} />{error}</div> : null}
          </div>

          <ResultAside
            title="Agent 执行报告"
            emptyIcon={Bot}
            emptyTitle="等待 Agent 任务"
            emptyText="提交后会显示运行阶段、事件流水和最终安全报告。"
            result={run || report}
          >
            <div className="agent-status-board">
              <MetricCard icon={Activity} label="任务状态" value={run?.status || "--"} hint={latestStage} />
              <MetricCard icon={ShieldCheck} label="风险等级" value={String(riskLevel)} hint="报告完成后更新" tone="indigo" />
            </div>
            <Timeline items={events.slice(-10)} />
            {report ? <ReportPreview report={report} /> : <EmptyState icon={Clock3} title="报告生成中" text="任务结束后将自动拉取报告。" />}
          </ResultAside>
        </div>
      </section>
    </main>
  );
}

function AdminPanel({ token }) {
  const [invites, setInvites] = useState([]);
  const [form, setForm] = useState({ code: "", maxUses: "1", expiresAt: "", note: "" });
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");

  const adminRequest = (url, options = {}) => fetchJson(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });

  const loadInvites = async () => {
    setLoading(true);
    setMessage("");
    try {
      const data = await adminRequest(`${SKILL_API}/api/admin/invites`);
      setInvites(data.invites || []);
    } catch (err) {
      setMessage(err.message || "获取邀请码失败。");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInvites();
  }, []);

  const createInvite = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setMessage("");
    try {
      await adminRequest(`${SKILL_API}/api/admin/invites`, {
        method: "POST",
        body: JSON.stringify({
          code: form.code.trim() || undefined,
          maxUses: Number(form.maxUses || 1),
          expiresAt: form.expiresAt || undefined,
          note: form.note.trim(),
        }),
      });
      setForm({ code: "", maxUses: "1", expiresAt: "", note: "" });
      await loadInvites();
    } catch (err) {
      setMessage(err.message || "创建邀请码失败。");
    } finally {
      setSubmitting(false);
    }
  };

  const disableInvite = async (code) => {
    setMessage("");
    try {
      await adminRequest(`${SKILL_API}/api/admin/invites/${encodeURIComponent(code)}/disable`, { method: "POST" });
      await loadInvites();
    } catch (err) {
      setMessage(err.message || "禁用邀请码失败。");
    }
  };

  const copyInvite = async (code) => {
    try {
      await navigator.clipboard.writeText(code);
      setMessage("邀请码已复制。");
    } catch {
      setMessage(code);
    }
  };

  return (
    <main className="page-grid task-layout">
      <section className="task-panel">
        <PanelHeader
          icon={KeyRound}
          title="管理员后台"
          subtitle="创建和管理注册邀请码，控制平台账号开通范围。"
          action={<button className="icon-button" type="button" onClick={loadInvites} title="刷新"><RefreshCcw size={17} /></button>}
        />
        <div className="admin-grid">
          <form className="admin-create-card" onSubmit={createInvite}>
            <PanelHeader icon={Sparkles} title="创建邀请码" subtitle="不填写邀请码时，系统会自动生成。" />
            <div className="form-grid two">
              <Field label="邀请码">
                <input value={form.code} onChange={(event) => setForm({ ...form, code: event.target.value })} placeholder="自动生成或自定义" />
              </Field>
              <Field label="可使用次数">
                <input min="1" type="number" value={form.maxUses} onChange={(event) => setForm({ ...form, maxUses: event.target.value })} />
              </Field>
            </div>
            <Field label="过期时间">
              <input type="datetime-local" value={form.expiresAt} onChange={(event) => setForm({ ...form, expiresAt: event.target.value })} />
            </Field>
            <Field label="备注">
              <input value={form.note} onChange={(event) => setForm({ ...form, note: event.target.value })} placeholder="例如：测试团队、外部评审、内部成员" />
            </Field>
            <button className="primary-button wide" disabled={submitting} type="submit">
              {submitting ? <RefreshCcw className="spin" size={18} /> : <CheckCircle2 size={18} />}
              {submitting ? "创建中" : "创建邀请码"}
            </button>
            {message ? <div className="admin-message">{message}</div> : null}
          </form>

          <section className="admin-list-card">
            <PanelHeader icon={ClipboardCheck} title="邀请码列表" subtitle={loading ? "正在刷新..." : `共 ${invites.length} 个邀请码`} />
            <div className="invite-list">
              {invites.length ? invites.map((invite) => {
                const exhausted = invite.usedCount >= invite.maxUses;
                const expired = invite.expiresAt && new Date(invite.expiresAt).getTime() < Date.now();
                const state = invite.status !== "active" ? "已禁用" : expired ? "已过期" : exhausted ? "已用完" : "可使用";
                return (
                  <article className="invite-card" key={invite.id || invite.code}>
                    <div>
                      <strong>{invite.code}</strong>
                      <p>{invite.note || "无备注"}</p>
                    </div>
                    <div className="invite-meta">
                      <span>{state}</span>
                      <span>{invite.usedCount}/{invite.maxUses}</span>
                      <span>{invite.expiresAt ? new Date(invite.expiresAt).toLocaleString() : "长期有效"}</span>
                    </div>
                    <div className="invite-actions">
                      <button className="ghost-button compact" type="button" onClick={() => copyInvite(invite.code)}>复制</button>
                      <button className="ghost-button compact danger" disabled={invite.status !== "active"} type="button" onClick={() => disableInvite(invite.code)}>禁用</button>
                    </div>
                  </article>
                );
              }) : <EmptyState icon={KeyRound} title="暂无邀请码" text="创建后，邀请码会显示在这里。" />}
            </div>
          </section>
        </div>
      </section>
    </main>
  );
}

function ResultAside({ title, result, emptyIcon, emptyTitle, emptyText, fallback, children }) {
  return (
    <aside className="result-aside">
      <PanelHeader icon={Gauge} title={title} />
      {result ? children : fallback || <EmptyState icon={emptyIcon} title={emptyTitle} text={emptyText} />}
    </aside>
  );
}

function getSkillRunStats(result) {
  const batchItems = Array.isArray(result?.skillResults) ? result.skillResults : [];
  const items = batchItems.length ? batchItems : result ? [result] : [];
  const total = Number(result?.skillCount || items.length || 1);
  const completedFallback = items.filter((item) => item?.executionStatus !== "failed" && item?.status !== "failed").length;
  const completed = Number(result?.completedCount ?? completedFallback);
  const failed = Number(result?.failedCount ?? Math.max(0, total - completed));
  return { items, batchItems, total, completed, failed };
}

function SkillRiskDashboard({ result }) {
  if (!result) return null;
  const score = Number(result.riskScore ?? 0);
  const level = result.riskLevelName || result.riskLevel || "未评级";
  const tone = getSkillRiskTone(result);
  const { batchItems, total, completed, failed } = getSkillRunStats(result);
  const behaviors = Array.isArray(result.detectedBehaviors) ? result.detectedBehaviors : [];
  const timeline = Array.isArray(result.evidenceTimeline) ? result.evidenceTimeline : [];
  const primaryFailure = result.runtimeFailure || batchItems.find((item) => item.runtimeFailure)?.runtimeFailure;
  const summary = result.riskSummary || primaryFailure?.message || "检测已完成，请结合风险等级、行为证据和执行时间线进行复核。";
  const verdict = buildSkillVerdict({ tone, level, score, failed, total, primaryFailure });

  return (
    <div className="skill-risk-dashboard">
      <section className={cx("risk-verdict-card", tone)}>
        <div className="risk-orb" style={{ "--score": Math.min(100, Math.max(0, score)) }}>
          {tone === "good" ? <ShieldCheck size={30} /> : tone === "warning" ? <ShieldAlert size={30} /> : <AlertTriangle size={30} />}
        </div>
        <div className="risk-verdict-copy">
          <span>{verdict.eyebrow}</span>
          <strong>{verdict.title}</strong>
          <p>{summary}</p>
        </div>
      </section>

      <div className="risk-action-card">
        <div>
          <strong>{verdict.actionTitle}</strong>
          <p>{verdict.actionText}</p>
        </div>
        <span>{level}</span>
      </div>

      <div className="risk-kpi-grid">
        <div>
          <span>风险评分</span>
          <strong>{score}</strong>
          <p>{level}</p>
        </div>
        <div>
          <span>检测完成</span>
          <strong>{completed}/{total}</strong>
          <p>{failed ? `${failed} 个未完成` : "全部完成"}</p>
        </div>
        <div>
          <span>命中行为</span>
          <strong>{behaviors.length}</strong>
          <p>{behaviors.length ? "需要复核" : "暂无明确命中"}</p>
        </div>
      </div>

      {result.batch ? <SkillBatchSummary results={batchItems} /> : null}
      <SkillFlowGraph result={result} />
      <EvidenceSpotlight behaviors={behaviors} timeline={timeline} />
      <SkillReportPages result={result} />
    </div>
  );
}


function SkillFlowGraph({ result }) {
  const graph = buildSkillFlowGraph(result);
  const [selectedId, setSelectedId] = useState(graph.nodes.find((node) => node.details.length)?.id || graph.nodes[0]?.id);
  const selected = graph.nodes.find((node) => node.id === selectedId) || graph.nodes[0];
  const hasDetails = selected && selected.details.length > 0;

  return (
    <section className="skill-flow-graph compact">
      <div className="skill-flow-head">
        <div className="mini-section-title">
          <Route size={16} />
          <strong>Skill 行为链路图</strong>
        </div>
        <div className="skill-flow-actions">
          <p>{graph.summary}</p>
        </div>
      </div>
      <SkillFlowMap graph={graph} selectedId={selectedId} onSelect={setSelectedId} />
      {hasDetails ? (
        <div className="skill-flow-detail">
          <div>
            <strong>{selected.label}</strong>
            <span>{selected.detail}</span>
          </div>
          <ol>
            {selected.details.map((item, index) => (
              <li key={`${selected.id}-${index}`}>
                <strong>{item.title || `明细 ${index + 1}`}</strong>
                {item.text ? <p>{item.text}</p> : null}
                {item.raw !== undefined ? <pre>{typeof item.raw === "string" ? item.raw : JSON.stringify(item.raw, null, 2)}</pre> : null}
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </section>
  );
}


function SkillFlowMap({ graph, selectedId, onSelect }) {
  const center = graph.nodes.find((node) => node.id === "risk") || graph.nodes[graph.nodes.length - 1];
  const satellites = graph.nodes.filter((node) => node.id !== center.id);
  const CenterIcon = center.icon;

  return (
    <div className="skill-flow-map" aria-label="Skill 行为链路图">
      <button
        type="button"
        className={cx("skill-flow-center", center.tone, selectedId === center.id && "active")}
        onClick={() => onSelect(center.id)}
      >
        <span><CenterIcon size={28} /></span>
        <strong>{center.value}</strong>
        <em>{center.label}</em>
        <small>{center.caption}</small>
      </button>
      <div className="skill-flow-ring">
        {satellites.map((node) => {
          const Icon = node.icon;
          return (
            <button
              type="button"
              className={cx("skill-flow-node", node.tone, selectedId === node.id && "active")}
              onClick={() => onSelect(node.id)}
              key={node.id}
            >
              <span className="skill-flow-icon"><Icon size={18} /></span>
              <span className="skill-flow-copy">
                <strong>{node.label}</strong>
                <em>{node.value}</em>
                <small>{node.caption}</small>
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}


function SkillReportPages({ result }) {
  const [active, setActive] = useState("report");
  return (
    <section className="risk-detail-panel report-pages">
      <div className="report-pages-head">
        <strong>检测结果</strong>
        <div className="report-tabs" role="tablist" aria-label="检测结果视图">
          <button type="button" className={cx(active === "report" && "active")} onClick={() => setActive("report")}>报告</button>
          <button type="button" className={cx(active === "json" && "active")} onClick={() => setActive("json")}>原始 JSON</button>
        </div>
      </div>
      <div className="report-page-body">
        {active === "report" ? (
          <SkillMarkdownReport result={result} />
        ) : (
          <div className="json-preview open-json">
            <pre>{JSON.stringify(result, null, 2)}</pre>
          </div>
        )}
      </div>
    </section>
  );
}


function buildSkillFlowGraph(result) {
  const items = Array.isArray(result?.skillResults) && result.skillResults.length ? result.skillResults : result ? [result] : [];
  const allFileEvents = collectSkillEvents(items, "fileEvents");
  const allProcessEvents = collectSkillEvents(items, "processEvents");
  const allToolCalls = collectSkillEvents(items, "toolCalls");
  const allNetworkEvents = collectSkillEvents(items, "networkEvents");
  const allLlmEvents = collectSkillEvents(items, "llmEvents");
  const allTimeline = collectSkillEvents(items, "evidenceTimeline");
  const behaviors = collectSkillEvents(items, "detectedBehaviors");
  const riskTone = getSkillRiskTone(result);
  const { total, completed, failed } = getSkillRunStats(result);
  const sampleNames = items.map((item) => item.skillName || item.skillFile || item.skillPath || "Skill").slice(0, 4);
  const runtimeNames = uniqueCompact(items.map((item) => item.runtimeName || item.sandboxImage || item.networkPolicy));
  const processToolCount = allProcessEvents.length + allToolCalls.length;
  const networkLlmCount = allNetworkEvents.length + allLlmEvents.length;

  const summaryParts = [
    `${completed}/${total} 个 Skill 完成`,
    `${allFileEvents.length} 条文件行为`,
    `${processToolCount} 条进程/工具行为`,
    `${networkLlmCount} 条网络/LLM 行为`,
  ];
  if (failed) summaryParts.push(`${failed} 个未完成`);

  return {
    summary: summaryParts.join("，"),
    nodes: [
      {
        id: "input",
        label: "输入样本",
        value: total > 1 ? `${total} 个 Skill` : sampleNames[0] || "Skill",
        caption: "上传内容",
        detail: "本次进入沙箱检测的 Skill 样本。",
        icon: FileArchive,
        tone: "info",
        details: buildInputFlowDetails(items),
      },
      {
        id: "sandbox",
        label: "沙箱执行",
        value: failed ? "部分未完成" : "执行完成",
        caption: runtimeNames[0] || result?.networkPolicy || "Docker 隔离",
        detail: failed ? "部分样本没有完整执行，建议先查看未完成原因。" : "样本已完成沙箱运行，并返回可视化证据。",
        icon: TerminalSquare,
        tone: failed ? "warning" : "good",
        details: buildEventFlowDetails(allTimeline, "执行事件", formatTimelineText),
      },
      {
        id: "files",
        label: "文件行为",
        value: `${allFileEvents.length} 条`,
        caption: allFileEvents.length ? "读写/访问" : "暂无命中",
        detail: "沙箱记录到的文件访问、读写或路径相关行为。",
        icon: FileSearch,
        tone: allFileEvents.length ? "warning" : "muted",
        details: buildEventFlowDetails(allFileEvents, "文件事件", formatFlowEvent),
      },
      {
        id: "process",
        label: "进程与工具",
        value: `${processToolCount} 条`,
        caption: allToolCalls.length ? "工具调用" : "进程线索",
        detail: "沙箱记录到的进程启动、命令执行或工具调用链路。",
        icon: Activity,
        tone: processToolCount ? "warning" : "muted",
        details: buildEventFlowDetails([...allProcessEvents, ...allToolCalls], "进程/工具事件", formatFlowEvent),
      },
      {
        id: "network",
        label: "网络与 LLM",
        value: `${networkLlmCount} 条`,
        caption: allNetworkEvents.length ? "外联线索" : allLlmEvents.length ? "LLM 事件" : "暂无命中",
        detail: "沙箱记录到的网络请求、域名访问或 LLM 相关事件。",
        icon: Network,
        tone: networkLlmCount ? "danger" : "muted",
        details: buildEventFlowDetails([...allNetworkEvents, ...allLlmEvents], "网络/LLM 事件", formatFlowEvent),
      },
      {
        id: "risk",
        label: "风险结论",
        value: result?.riskLevelName || result?.riskLevel || "未知",
        caption: `${Number(result?.riskScore || 0)} 分 / ${behaviors.length} 个行为`,
        detail: result?.riskSummary || "请结合风险评分、命中行为和链路证据进行复核。",
        icon: riskTone === "good" ? ShieldCheck : riskTone === "danger" ? ShieldAlert : ShieldQuestion,
        tone: riskTone,
        details: buildRiskFlowDetails(result, behaviors),
      },
    ],
  };
}


function collectSkillEvents(items, key) {
  return items.flatMap((item) => Array.isArray(item?.[key]) ? item[key] : []);
}


function uniqueCompact(items) {
  return [...new Set(items.filter(Boolean).map((item) => String(item)))];
}


function buildInputFlowDetails(items) {
  return items.map((item, index) => ({
    title: item?.skillName || item?.skillFile || `Skill ${index + 1}`,
    text: [
      item?.skillPath ? `路径：${item.skillPath}` : "",
      item?.executionStatus ? `执行状态：${item.executionStatus}` : "",
      item?.riskLevelName || item?.riskLevel ? `风险等级：${item.riskLevelName || item.riskLevel}` : "",
      Number.isFinite(Number(item?.riskScore)) ? `风险评分：${Number(item.riskScore)}` : "",
    ].filter(Boolean).join("；"),
    raw: {
      skillName: item?.skillName,
      skillFile: item?.skillFile,
      skillPath: item?.skillPath,
      executionStatus: item?.executionStatus,
      riskScore: item?.riskScore,
      riskLevel: item?.riskLevel,
      riskLevelName: item?.riskLevelName,
    },
  }));
}


function buildEventFlowDetails(items, titlePrefix, formatter) {
  return items.map((item, index) => ({
    title: `${titlePrefix} ${index + 1}`,
    text: formatter(item),
    raw: item,
  }));
}


function buildRiskFlowDetails(result, behaviors) {
  const details = [];
  if (result?.riskSummary || result?.riskLevel || result?.riskLevelName || result?.riskScore !== undefined) {
    details.push({
      title: "风险结论",
      text: result?.riskSummary || "检测已完成，请结合证据进行人工复核。",
      raw: {
        riskScore: result?.riskScore,
        riskLevel: result?.riskLevel,
        riskLevelName: result?.riskLevelName,
        primaryRisk: result?.primaryRisk,
        riskLabels: result?.riskLabels,
        finalDecision: result?.finalDecision,
        rootCause: result?.rootCause,
        rootCauseDetail: result?.rootCauseDetail,
      },
    });
  }
  behaviors.forEach((item, index) => {
    details.push({
      title: `命中行为 ${index + 1}`,
      text: formatEvidenceText(item),
      raw: item,
    });
  });
  return details;
}


function formatFlowEvent(item) {
  if (typeof item === "string") return humanizeEvidenceKey(item);
  if (!item || typeof item !== "object") return String(item ?? "");
  const label = item.label || item.description || item.summary || item.action || item.type || item.name || item.tool || item.command || item.method;
  const target = item.path || item.file || item.url || item.host || item.domain || item.target || item.destination || item.args;
  const status = item.status || item.result || item.exitCode;
  return [label, target, status].filter((part) => part !== undefined && part !== null && String(part).trim()).map((part) => String(part)).join(" · ");
}


function SkillMarkdownReport({ result }) {
  const markdown = result?.markdownReport || result?.markdown_report || buildClientSkillMarkdownReport(result);
  return (
    <div className="skill-markdown-report">
      <RenderedMarkdown markdown={markdown} />
    </div>
  );
}


function RenderedMarkdown({ markdown }) {
  const blocks = parseSimpleMarkdown(markdown);
  return blocks.map((block, index) => {
    const key = `${block.type}-${index}`;
    if (block.type === "heading") {
      const Tag = `h${Math.min(3, Math.max(1, block.level))}`;
      return <Tag key={key}>{block.text}</Tag>;
    }
    if (block.type === "list") {
      return (
        <ul key={key}>
          {block.items.map((item, itemIndex) => <li key={`${key}-${itemIndex}`}>{item}</li>)}
        </ul>
      );
    }
    if (block.type === "code") {
      return <pre key={key}><code>{block.text}</code></pre>;
    }
    return <p key={key}>{block.text}</p>;
  });
}


function parseSimpleMarkdown(markdown) {
  const lines = String(markdown || "").replace(/\r\n/g, "\n").split("\n");
  const blocks = [];
  let paragraph = [];
  let list = [];
  let code = [];
  let inCode = false;

  const flushParagraph = () => {
    const text = paragraph.join(" ").trim();
    if (text) blocks.push({ type: "paragraph", text });
    paragraph = [];
  };
  const flushList = () => {
    if (list.length) blocks.push({ type: "list", items: list });
    list = [];
  };

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (line.trim().startsWith("```")) {
      if (inCode) {
        blocks.push({ type: "code", text: code.join("\n") });
        code = [];
        inCode = false;
      } else {
        flushParagraph();
        flushList();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      code.push(rawLine);
      continue;
    }
    if (!line.trim()) {
      flushParagraph();
      flushList();
      continue;
    }
    const heading = /^(#{1,3})\s+(.+)$/.exec(line);
    if (heading) {
      flushParagraph();
      flushList();
      blocks.push({ type: "heading", level: heading[1].length, text: heading[2].trim() });
      continue;
    }
    const bullet = /^[-*]\s+(.+)$/.exec(line);
    if (bullet) {
      flushParagraph();
      list.push(bullet[1].trim());
      continue;
    }
    flushList();
    paragraph.push(line.trim());
  }

  if (inCode) blocks.push({ type: "code", text: code.join("\n") });
  flushParagraph();
  flushList();
  return blocks;
}


function buildClientSkillMarkdownReport(result) {
  if (!result) return "";
  const items = Array.isArray(result.skillResults) && result.skillResults.length ? result.skillResults : [result];
  const { total, completed, failed } = getSkillRunStats(result);
  const behaviors = Array.isArray(result.detectedBehaviors) ? result.detectedBehaviors : [];
  const timeline = Array.isArray(result.evidenceTimeline) ? result.evidenceTimeline : [];
  const lines = [
    "# Skill 动态沙箱检测报告",
    "",
    "## 总览",
    "",
    `- 检测状态：${completed}/${total} 完成${failed ? `，${failed} 个未完成` : "，全部完成"}`,
    `- 风险评分：${Number(result.riskScore || 0)}`,
    `- 风险等级：${result.riskLevelName || result.riskLevel || "未知"}`,
    "",
    "## 结论",
    "",
    result.riskSummary || "检测已完成，请结合证据进行人工复核。",
    "",
  ];

  if (behaviors.length) {
    lines.push("## 命中行为", "");
    behaviors.slice(0, 12).forEach((item) => lines.push(`- ${humanizeEvidenceKey(item)}`));
    lines.push("");
  }

  const failures = items.filter((item) => item.executionStatus === "failed" || item.runtimeFailure);
  if (failures.length) {
    lines.push("## 未完成原因", "");
    failures.forEach((item) => {
      const failure = item.runtimeFailure || {};
      lines.push(`- ${item.skillName || item.skillFile || "Skill"}：${failure.title || "运行未完成"}。${failure.message || "沙箱没有返回足够证据。"}`);
    });
    lines.push("");
  }

  lines.push("## 样本结果", "");
  items.slice(0, 20).forEach((item) => {
    lines.push(`### ${item.skillName || item.skillFile || "Skill"}`);
    lines.push("");
    lines.push(`- 状态：${item.executionStatus === "completed" ? "完成" : "未完成"}`);
    lines.push(`- 分数：${Number(item.riskScore || 0)}`);
    lines.push(`- 等级：${item.riskLevelName || item.riskLevel || "未知"}`);
    if (item.riskSummary || item.runtimeFailure?.message) {
      lines.push(`- 摘要：${item.riskSummary || item.runtimeFailure.message}`);
    }
    lines.push("");
  });

  if (timeline.length) {
    lines.push("## 执行线索", "");
    timeline.slice(0, 12).forEach((item) => lines.push(`- ${formatTimelineText(item)}`));
    lines.push("");
  }

  lines.push("## 复核建议", "");
  lines.push("- 高分或命中文件写入、进程启动、网络访问、敏感读取时，建议人工复核 SKILL.md、动作定义和运行证据。");
  lines.push("- 只有出现未完成原因时，才把结果视为环境或外部依赖阻塞；否则以风险评分和命中行为为主要结论。");
  return `${lines.join("\n")}\n`;
}


function EvidenceSpotlight({ behaviors, timeline }) {
  const behaviorItems = Array.isArray(behaviors) ? behaviors.slice(0, 4) : [];
  const timelineItems = Array.isArray(timeline) ? timeline.slice(0, 4) : [];
  const [selected, setSelected] = useState(null);
  const selectedDetail = selected?.kind === "behavior"
    ? {
      title: "关键行为详情",
      text: formatEvidenceText(selected.item),
      raw: selected.item,
    }
    : selected?.kind === "timeline"
      ? {
        title: "执行线索详情",
        text: formatTimelineText(selected.item),
        raw: selected.item,
      }
      : null;
  return (
    <section className="evidence-spotlight">
      <div className="evidence-column">
        <div className="mini-section-title">
          <Route size={16} />
          <strong>关键行为</strong>
        </div>
        {behaviorItems.length ? behaviorItems.map((item, index) => (
          <button className="evidence-pill" type="button" onClick={() => setSelected({ kind: "behavior", item, index })} key={`${String(item)}-${index}`}>
            <span>{index + 1}</span>
            <p>{formatEvidenceText(item)}</p>
          </button>
        )) : <div className="friendly-empty">暂无明确可疑行为命中。</div>}
      </div>
      <div className="evidence-column">
        <div className="mini-section-title">
          <Clock3 size={16} />
          <strong>执行线索</strong>
        </div>
        {timelineItems.length ? timelineItems.map((item, index) => (
          <button className="evidence-pill timeline" type="button" onClick={() => setSelected({ kind: "timeline", item, index })} key={`${item.timestamp || item.time || index}-${index}`}>
            <span>{index + 1}</span>
            <p>{formatTimelineText(item)}</p>
          </button>
        )) : <div className="friendly-empty">暂无可展示的执行事件。</div>}
      </div>
      {selectedDetail ? (
        <div className="evidence-detail-card">
          <div>
            <strong>{selectedDetail.title}</strong>
            <button className="ghost-button compact" type="button" onClick={() => setSelected(null)}>收起</button>
          </div>
          <p>{selectedDetail.text}</p>
          {typeof selectedDetail.raw === "object" ? <pre>{JSON.stringify(selectedDetail.raw, null, 2)}</pre> : null}
        </div>
      ) : null}
    </section>
  );
}

function getSkillRiskTone(result) {
  const level = String(result?.riskLevel || result?.riskLevelName || "").toLowerCase();
  const score = Number(result?.riskScore || 0);
  const { failed } = getSkillRunStats(result);
  if (result?.executionStatus === "failed" || result?.status === "failed" || failed > 0 || level.includes("未完成")) return "warning";
  if (level.includes("critical") || level.includes("high") || level.includes("高") || score >= 70) return "danger";
  if (level.includes("medium") || level.includes("中") || score >= 35) return "warning";
  return "good";
}

function buildSkillVerdict({ tone, level, score, failed, total, primaryFailure }) {
  if (primaryFailure || failed > 0) {
    return {
      eyebrow: "检测状态",
      title: "检测未完全完成",
      actionTitle: "建议先处理阻塞原因",
      actionText: primaryFailure?.message || `本次 ${total} 个 Skill 中有 ${failed} 个未完成，暂时不要把当前结果作为低风险结论。`,
    };
  }
  if (tone === "danger") {
    return {
      eyebrow: "风险结论",
      title: "发现高风险行为",
      actionTitle: "建议暂缓上线并人工复核",
      actionText: `当前等级为 ${level}，评分 ${score}。请优先查看关键行为和执行线索。`,
    };
  }
  if (tone === "warning") {
    return {
      eyebrow: "风险结论",
      title: "存在需要复核的行为",
      actionTitle: "建议结合证据确认是否放行",
      actionText: `当前等级为 ${level}，评分 ${score}。建议查看行为证据后再决定。`,
    };
  }
  return {
    eyebrow: "风险结论",
    title: "暂未发现明显高风险",
    actionTitle: "可以进入常规复核",
    actionText: "当前检测未命中明显高风险行为，仍建议保留报告用于审计。",
  };
}


function formatEvidenceText(item) {
  if (typeof item === "string") return humanizeEvidenceKey(item);
  return item?.label || item?.description || item?.type || JSON.stringify(item);
}

function formatTimelineText(item) {
  if (!item || typeof item !== "object") return String(item || "");
  return item.summary || item.message || item.event || item.action || item.type || JSON.stringify(item).slice(0, 120);
}

function humanizeEvidenceKey(value) {
  const text = String(value || "");
  const labels = {
    runtime_incomplete: "运行未完成，结果不能直接作为低风险结论",
    network_connect: "检测到网络连接行为",
    file_read: "检测到文件读取行为",
    file_write: "检测到文件写入行为",
    process_spawn: "检测到进程启动行为",
    llm_request: "检测到模型调用行为",
  };
  return labels[text] || text.replaceAll("_", " ");
}

function RiskSummary({ score, level }) {
  return (
    <div className="risk-summary">
      <div className="risk-gauge" style={{ "--score": Math.min(100, Math.max(0, score)) }}>
        <div>
          <strong>{score}</strong>
          <span>{level}</span>
        </div>
      </div>
      <div className="risk-copy">
        <strong>风险判定</strong>
        <p>分数越高表示越需要人工复核。请结合行为证据和时间线确认是否阻断上线。</p>
      </div>
    </div>
  );
}

function SkillBatchSummary({ results }) {
  const items = Array.isArray(results) ? results : [];
  if (!items.length) return null;
  const completed = items.filter((item) => item.executionStatus === "completed").length;
  const failed = items.length - completed;

  return (
    <div className="batch-summary">
      <div className="batch-heading">
        <strong>批量检测结果</strong>
        <span>{completed} 完成 / {failed} 未完成</span>
      </div>
      {items.slice(0, 8).map((item) => (
        <div className={cx("batch-row", item.executionStatus === "failed" && "failed")} key={item.executionId || item.skillPath}>
          <div>
            <strong>{item.skillName || item.skillFile || "Skill"}</strong>
            <p>{item.runtimeFailure?.message || item.riskSummary || item.skillFile || item.skillPath}</p>
          </div>
          <span>{item.executionStatus === "failed" ? "未完成" : item.riskScore ?? 0}</span>
        </div>
      ))}
    </div>
  );
}

function BehaviorList({ items }) {
  const data = Array.isArray(items) && items.length ? items : ["暂未发现需要重点关注的行为"];
  return (
    <div className="behavior-list">
      {data.slice(0, 6).map((item, index) => (
        <div className="behavior-item" key={`${String(item)}-${index}`}>
          <Route size={14} />
          <span>{typeof item === "string" ? item : item?.label || item?.type || JSON.stringify(item)}</span>
        </div>
      ))}
    </div>
  );
}

function ReportPreview({ report }) {
  const markdown = report.markdown_report || report.markdown || "";
  return (
    <div className="report-preview">
      <h3>最终报告</h3>
      {markdown ? <pre>{markdown.slice(0, 3200)}</pre> : <JsonPreview data={report} />}
    </div>
  );
}

function normalizeAgentRisk(value) {
  const key = String(value || "unknown").toLowerCase();
  if (["critical", "high"].includes(key)) {
    return {
      label: key === "critical" ? "严重风险" : "高风险",
      tone: "danger",
      icon: <AlertTriangle size={28} />,
      recommendation: "建议暂缓上线，优先复核高风险发现和动态执行证据。",
    };
  }
  if (key === "medium") {
    return {
      label: "中风险",
      tone: "warning",
      icon: <ShieldAlert size={28} />,
      recommendation: "建议完成发现项复核后再进入受控环境试运行。",
    };
  }
  if (["low", "info"].includes(key)) {
    return {
      label: "低风险",
      tone: "good",
      icon: <ShieldCheck size={28} />,
      recommendation: "未发现明显阻断项，仍建议保留最小权限和运行审计。",
    };
  }
  return {
    label: "待复核",
    tone: "neutral",
    icon: <ShieldQuestion size={28} />,
    recommendation: "报告已生成，请结合检测事件和发现项进行人工复核。",
  };
}

function normalizeBuildStatus(value) {
  const key = String(value || "").toLowerCase();
  if (["built", "success", "succeeded", "completed"].includes(key)) {
    return {
      label: "构建成功",
      tone: "good",
      title: "项目环境已成功构建",
      reason: "沙箱已完成依赖安装和运行环境准备。",
      fix: "可以继续查看动态运行证据和风险发现。",
    };
  }
  if (key === "cached") {
    return {
      label: "复用缓存",
      tone: "good",
      title: "已复用历史构建环境",
      reason: "本次检测命中可用缓存，未重复构建镜像。",
      fix: "如依赖发生变化，可选择重新构建后再检测。",
    };
  }
  if (key === "skipped") {
    return {
      label: "已跳过",
      tone: "warning",
      title: "未执行构建阶段",
      reason: "当前样本缺少可识别的构建入口，或配置要求跳过构建。",
      fix: "如需完整动态运行，请在项目中提供 Dockerfile、sandbox.yaml 或常见依赖清单。",
    };
  }
  if (key === "failed") {
    return {
      label: "构建受阻",
      tone: "danger",
      title: "沙箱环境构建没有完成",
      reason: "依赖镜像、软件源或项目安装脚本在构建阶段未能成功执行。",
      fix: "请优先检查 Docker 镜像源、网络连通性、依赖凭据，或为样本补充 sandbox.yaml。",
    };
  }
  return {
    label: "未记录",
    tone: "neutral",
    title: "未记录构建状态",
    reason: "报告中没有返回构建阶段状态。",
    fix: "可结合运行事件确认任务是否进入动态执行阶段。",
  };
}

function normalizeBuildMessage(message, failureClass, type) {
  const key = String(failureClass || "").toLowerCase();
  const text = String(message || "").toLowerCase();

  if (key === "auth_required" || text.includes("requires authentication") || text.includes("unauthorized")) {
    return type === "reason"
      ? "构建过程中访问镜像源、代码依赖或模型配置时需要认证，当前沙箱无法继续完成环境准备。"
      : "请检查镜像源是否可访问，改用可用的国内镜像，或在项目中固定依赖并补充 sandbox.yaml 后重新检测。";
  }

  if (key === "network_timeout" || text.includes("timeout") || text.includes("connection")) {
    return type === "reason"
      ? "构建阶段访问外部镜像源或依赖服务超时，沙箱环境没有完成准备。"
      : "请确认 Docker 网络可用后重试，必要时切换镜像源或提前准备基础镜像。";
  }

  if (key === "unsupported_project") {
    return type === "reason"
      ? "当前上传内容缺少可识别的启动或构建入口，平台无法自动判断如何运行。"
      : "请上传完整项目目录，或在项目根目录添加 Dockerfile / sandbox.yaml / package.json / pyproject.toml 等运行配置。";
  }

  if (key === "build_script_failed" || text.includes("build script") || text.includes("install script")) {
    return type === "reason"
      ? "项目依赖安装或构建脚本执行失败，沙箱没有得到可运行环境。"
      : "请检查项目依赖、安装脚本和系统包要求，必要时在 sandbox.yaml 中写明安装与启动命令。";
  }

  return "";
}

function normalizeSeverity(value) {
  const key = String(value || "info").toLowerCase();
  if (["critical", "high"].includes(key)) return { label: key === "critical" ? "严重" : "高", tone: "danger" };
  if (key === "medium") return { label: "中", tone: "warning" };
  if (key === "low") return { label: "低", tone: "good" };
  return { label: "信息", tone: "neutral" };
}

function normalizeDynamicStatus(value) {
  const key = String(value || "").toLowerCase();
  if (key === "completed") return "已完成";
  if (key === "dynamic_failed") return "运行受阻";
  if (key === "docker_unavailable") return "Docker 未就绪";
  if (key === "running") return "运行中";
  if (key === "failed") return "失败";
  return String(value || "已完成");
}

function App() {
  const [activePage, setActivePage] = useState("overview");
  const [token, setToken] = useState(() => sessionStorage.getItem("asguard_console_token") || sessionStorage.getItem("sandbox_console_token") || "");
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(sessionStorage.getItem("asguard_console_user") || sessionStorage.getItem("sandbox_console_user") || "null");
    } catch {
      return null;
    }
  });
  const { status, refresh } = useServiceStatus();

  const handleAuthenticated = (data) => {
    const nextToken = data?.token || "";
    const nextUser = data?.user || null;
    setToken(nextToken);
    setUser(nextUser);
    sessionStorage.setItem("asguard_console_token", nextToken);
    sessionStorage.setItem("asguard_console_user", JSON.stringify(nextUser));
    sessionStorage.removeItem("sandbox_console_token");
    sessionStorage.removeItem("sandbox_console_user");
  };

  const logout = () => {
    setToken("");
    setUser(null);
    setActivePage("overview");
    sessionStorage.removeItem("asguard_console_token");
    sessionStorage.removeItem("asguard_console_user");
    sessionStorage.removeItem("sandbox_console_token");
    sessionStorage.removeItem("sandbox_console_user");
  };

  const visibleNavItems = navItems.filter((item) => !item.adminOnly || user?.role === "admin");

  const page = useMemo(() => {
    if (activePage === "admin") return user?.role === "admin" ? <AdminPanel token={token} /> : <OverviewPage serviceStatus={status} onNavigate={setActivePage} onRefresh={refresh} />;
    if (activePage === "skill") return <SkillPanel serviceStatus={status} onRefresh={refresh} token={token} onAuthExpired={logout} />;
    if (activePage === "agent") return <AgentPanel serviceStatus={status} onRefresh={refresh} />;
    return <OverviewPage serviceStatus={status} onNavigate={setActivePage} onRefresh={refresh} />;
  }, [activePage, status, token, user]);

  if (!token) {
    return (
      <div className="app-shell">
        <AuthPage onAuthenticated={handleAuthenticated} />
      </div>
    );
  }

  return (
    <div className="app-shell">
      <header className="site-header">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={25} />
          </div>
          <div>
            <strong>ASGuard</strong>
            <span>Skill 与 Agent 安全检测</span>
          </div>
        </div>
        <nav className="top-nav">
          {visibleNavItems.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.id} className={cx(activePage === item.id && "active")} type="button" onClick={() => setActivePage(item.id)}>
                <Icon size={19} />
                {item.label}
              </button>
            );
          })}
        </nav>
        <div className="service-status-bar">
          <div>
            <span>{user?.username || "已登录"}</span>
            <button className="logout-button" type="button" onClick={logout}>
              退出
            </button>
          </div>
          <div>
            <span>Skill 服务</span>
            <StatusPill state={status.skill.state} label={status.skill.label} />
          </div>
          <div>
            <span>Agent 服务</span>
            <StatusPill state={status.agent.state} label={status.agent.label} />
          </div>
        </div>
      </header>

      <div className="main-shell">
        <header className="topbar">
          <div>
            <h1>{visibleNavItems.find((item) => item.id === activePage)?.label || "总览"}</h1>
            <p>上传检测对象，选择检测策略，获取可复核的安全证据。</p>
          </div>
          <button className="secondary-button" type="button" onClick={refresh}>
            <RefreshCcw size={17} />
            刷新状态
          </button>
        </header>
        {page}
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
