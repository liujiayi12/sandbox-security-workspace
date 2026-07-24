import {
  Activity,
  Bot,
  CheckCircle2,
  FileArchive,
  Globe,
  Shield,
  Sparkles,
  Workflow,
} from "lucide-react";

const capabilities = [
  {
    icon: FileArchive,
    title: "上传 Agent 包",
    text: "支持 .zip 智能体压缩包上传，快速进入静态扫描与风险分析流程。",
  },
  {
    icon: Shield,
    title: "静态风险扫描",
    text: "基于 sandbox.yaml、Dockerfile、依赖清单与 README 提示完成风险识别。",
  },
  {
    icon: Workflow,
    title: "动态沙箱执行",
    text: "通过 Docker 硬化隔离、网络策略与攻击探针完成受控环境验证。",
  },
  {
    icon: Globe,
    title: "Fake Environment",
    text: "结合 OpenAI、邮件、GitHub、RAG、浏览器与状态机对象进行多面交互测试。",
  },
];

const pipeline = [
  "上传 Agent 压缩包与可选模型配置",
  "执行静态扫描、BuildPlan 发现与镜像预热",
  "动态运行候选方案并进行安全攻击探针",
  "输出面向用户的 Markdown 风险报告",
];

const metrics = [
  { label: "扫描模块", value: "6" },
  { label: "Run Policy", value: "auto / strict" },
  { label: "镜像保留", value: "一级可删" },
  { label: "运行环境", value: "sandbox / bridge" },
];

export default function AIAgentSandboxPage() {
  return (
    <div className="ai-agent-page">
      <section className="ai-agent-hero">
        <div className="ai-agent-hero-copy">
          <div className="ai-agent-pill">AegisAgent × ClawGuard</div>
          <h2 className="ai-agent-title">AI Agent 安全测试联合控制台</h2>
          <p className="ai-agent-subtitle">
            统一展示 AegisAgent 的智能体上传、静态扫描、动态沙箱测试与风险报告能力，
            同时结合 ClawGuard 的安全治理入口风格，构建可视化的前端页面。
          </p>
        </div>

        <div className="ai-agent-hero-panel">
          <div className="ai-agent-hero-stat-row">
            {metrics.map((item) => (
              <div className="ai-agent-stat-card" key={item.label}>
                <div className="ai-agent-stat-value">{item.value}</div>
                <div className="ai-agent-stat-label">{item.label}</div>
              </div>
            ))}
          </div>
          <div className="ai-agent-hero-cta-row">
            <button type="button" className="oc-primary-btn ai-agent-cta-btn">
              上传 Agent Zip
            </button>
            <button type="button" className="oc-ghost-btn ai-agent-cta-btn">
              查看风险报告
            </button>
          </div>
        </div>
      </section>

      <section className="ai-agent-grid">
        {capabilities.map((item) => {
          const Icon = item.icon;
          return (
            <article className="ai-agent-card" key={item.title}>
              <div className="ai-agent-card-icon">
                <Icon size={18} strokeWidth={1.9} />
              </div>
              <h3>{item.title}</h3>
              <p>{item.text}</p>
            </article>
          );
        })}
      </section>

      <section className="ai-agent-workflow">
        <div className="ai-agent-section-head">
          <div className="ai-agent-section-kicker">
            <Sparkles size={14} strokeWidth={2} />
            <span>安全执行链路</span>
          </div>
          <h3>从上传到告警输出的完整闭环</h3>
        </div>

        <div className="ai-agent-workflow-body">
          <div className="ai-agent-workflow-list">
            {pipeline.map((step, index) => (
              <div className="ai-agent-workflow-item" key={step}>
                <div className="ai-agent-workflow-index">{index + 1}</div>
                <div className="ai-agent-workflow-copy">{step}</div>
              </div>
            ))}
          </div>

          <div className="ai-agent-run-summary">
            <div className="ai-agent-summary-row">
              <Bot size={16} strokeWidth={2} />
              <span>智能分析引擎</span>
            </div>
            <div className="ai-agent-summary-row">
              <Activity size={16} strokeWidth={2} />
              <span>进度：执行中 / 已完成</span>
            </div>
            <div className="ai-agent-summary-row">
              <Shield size={16} strokeWidth={2} />
              <span>输出：可下载 Markdown 报告</span>
            </div>
            <div className="ai-agent-summary-row">
              <CheckCircle2 size={16} strokeWidth={2} />
              <span>沙箱：默认断网、可配置 bridge 模式</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
