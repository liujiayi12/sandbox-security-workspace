import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  Archive,
  Bot,
  CheckCircle2,
  ChevronRight,
  Clock3,
  FileArchive,
  FileCode2,
  Gauge,
  Info,
  KeyRound,
  LayoutDashboard,
  Lock,
  Network,
  Play,
  Radar,
  RefreshCcw,
  Route,
  Settings2,
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
      <summary>详细记录</summary>
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </details>
  );
}

function OverviewPage({ serviceStatus, onNavigate, onRefresh }) {
  const onlineCount = [serviceStatus.skill, serviceStatus.agent].filter((item) => item.state === "online").length;
  const capacity = serviceStatus.capacity;

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
        </div>
        <div className="hero-visual" aria-hidden="true">
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
        <MetricCard icon={Activity} label="Skill 任务余量" value={capacity ? `${capacity.available}/${capacity.limit}` : "--"} hint="当前可并发处理数量" tone="cyan" />
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
            text="对 SKILL.md 或 Skill 压缩包进行隔离执行，输出风险画像、行为证据和时间线。"
            status={serviceStatus.skill}
            onClick={() => onNavigate("skill")}
          />
          <FeatureCard
            icon={Bot}
            title="Agent 安全分析"
            text="上传 Agent zip 后自动识别结构、生成运行计划，并在隔离环境中产出检测报告。"
            status={serviceStatus.agent}
            onClick={() => onNavigate("agent")}
          />
        </div>
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

function SkillPanel({ serviceStatus, onRefresh }) {
  const [files, setFiles] = useState([]);
  const [sourceUrl, setSourceUrl] = useState("");
  const [preset, setPreset] = useState("balanced");
  const [customPrompt, setCustomPrompt] = useState("");
  const [token, setToken] = useState(() => sessionStorage.getItem("sandbox_console_token") || "");
  const [llmEnabled, setLlmEnabled] = useState(false);
  const [llmApiKey, setLlmApiKey] = useState("");
  const [llmModel, setLlmModel] = useState("deepseek-ai/DeepSeek-V3");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    sessionStorage.setItem("sandbox_console_token", token);
  }, [token]);

  const selected = skillPresets[preset];
  const canRun = files.length > 0 || sourceUrl.trim();

  const runScan = async () => {
    setError("");
    setResult(null);
    setRunning(true);
    try {
      const uploadFiles = await Promise.all(
        files.map(async (file) => ({
          name: file.name,
          relativePath: file.webkitRelativePath || file.name,
          contentBase64: await readAsBase64(file),
        })),
      );

      const payload = {
        files: uploadFiles,
        sourceUrl: sourceUrl.trim(),
        inputPayload: { prompt: customPrompt.trim() || selected.prompt },
        timeoutSeconds: selected.timeoutSeconds,
        networkPolicy: selected.networkPolicy,
        analysisMode: selected.analysisMode,
        llmConfig: {
          enabled: llmEnabled,
          provider: "siliconflow",
          base_url: "https://api.siliconflow.cn/v1",
          model: llmModel,
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
      setError(err.status === 401 ? "当前后端要求登录授权。请在高级设置中填写访问令牌后重试。" : err.message || "动态检测失败");
    } finally {
      setRunning(false);
    }
  };

  const riskScore = Number(result?.riskScore ?? 0);
  const behaviors = Array.isArray(result?.detectedBehaviors) ? result.detectedBehaviors : [];
  const timeline = Array.isArray(result?.evidenceTimeline) ? result.evidenceTimeline : [];
  const currentStep = result ? 2 : canRun ? 1 : 0;

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

        <div className="task-grid">
          <div className="task-main">
            <FileDrop
              accept=".zip,.md,.txt,.json,.yaml,.yml"
              files={files}
              onFiles={setFiles}
              icon={FileCode2}
              title="上传 Skill 文件或压缩包"
              description="推荐上传包含 SKILL.md 的完整目录压缩包，也可以直接上传单个 SKILL.md。"
            />
            <FileList files={files} onClear={() => setFiles([])} />
          <Field label="或填写远程地址" hint="支持可直接下载的 SKILL.md 或 zip 链接。">
              <input value={sourceUrl} onChange={(event) => setSourceUrl(event.target.value)} placeholder="https://example.com/SKILL.md" />
            </Field>
            <Field label="检测策略">
              <PresetSelector presets={skillPresets} value={preset} onChange={setPreset} />
            </Field>
            <AdvancedBox>
              <Field label="自定义执行意图" hint="留空时使用所选策略的默认意图。">
                <textarea value={customPrompt} onChange={(event) => setCustomPrompt(event.target.value)} placeholder={selected.prompt} />
              </Field>
              <div className="form-grid two">
              <Field label="授权凭证">
                <input value={token} onChange={(event) => setToken(event.target.value)} placeholder="服务要求身份校验时填写" />
                </Field>
                <Field label="LLM 模型">
                  <input value={llmModel} onChange={(event) => setLlmModel(event.target.value)} />
                </Field>
              </div>
              <label className="check-row">
                <input type="checkbox" checked={llmEnabled} onChange={(event) => setLlmEnabled(event.target.checked)} />
                <span>启用 LLM 辅助解释</span>
              </label>
              <Field label="LLM API Key">
                <input type="password" value={llmApiKey} onChange={(event) => setLlmApiKey(event.target.value)} placeholder="可选" />
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
          >
            <RiskSummary score={riskScore} level={result?.riskLevelName || result?.riskLevel || "未评级"} />
            <BehaviorList items={behaviors} />
            <Timeline items={timeline} />
            <JsonPreview data={result} />
          </ResultAside>
        </div>
      </section>
    </main>
  );
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

function ResultAside({ title, result, emptyIcon, emptyTitle, emptyText, children }) {
  return (
    <aside className="result-aside">
      <PanelHeader icon={Gauge} title={title} />
      {result ? children : <EmptyState icon={emptyIcon} title={emptyTitle} text={emptyText} />}
    </aside>
  );
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
        <p>分数越高表示越需要人工复核。结合行为证据和时间线确认是否阻断上线。</p>
      </div>
    </div>
  );
}

function BehaviorList({ items }) {
  const data = Array.isArray(items) && items.length ? items : ["后端尚未返回行为证据"];
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

function App() {
  const [activePage, setActivePage] = useState("overview");
  const { status, refresh } = useServiceStatus();

  const page = useMemo(() => {
    if (activePage === "skill") return <SkillPanel serviceStatus={status} onRefresh={refresh} />;
    if (activePage === "agent") return <AgentPanel serviceStatus={status} onRefresh={refresh} />;
    return <OverviewPage serviceStatus={status} onNavigate={setActivePage} onRefresh={refresh} />;
  }, [activePage, status]);

  return (
    <div className="app-shell">
      <header className="site-header">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={25} />
          </div>
          <div>
            <strong>Sandbox Console</strong>
            <span>Skill 与 Agent 安全检测</span>
          </div>
        </div>
        <nav className="top-nav">
          {navItems.map((item) => {
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
            <h1>{navItems.find((item) => item.id === activePage)?.label || "总览"}</h1>
            <p>上传检测对象，选择策略，获取可复核的安全证据。</p>
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
