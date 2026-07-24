const providerDefaults = {
  none: { baseUrl: "", model: "" },
  openai: { baseUrl: "https://api.openai.com/v1", model: "gpt-4o-mini" },
  deepseek: { baseUrl: "https://api.deepseek.com/v1", model: "deepseek-chat" },
  siliconflow: { baseUrl: "https://api.siliconflow.cn/v1", model: "deepseek-ai/DeepSeek-V3" },
  custom: { baseUrl: "", model: "" },
};

const form = document.querySelector("#run-form");
const fileInput = document.querySelector("#agent-file");
const fileTitle = document.querySelector("#file-title");
const fileMeta = document.querySelector("#file-meta");
const providerInput = document.querySelector("#provider");
const modelInput = document.querySelector("#model");
const baseUrlInput = document.querySelector("#base-url");
const apiKeyInput = document.querySelector("#api-key");
const toggleKeyButton = document.querySelector("#toggle-key");
const keyState = document.querySelector("#key-state");
const noKeyWarning = document.querySelector("#no-key-warning");
const llmOptions = document.querySelector("#llm-options");
const submitButton = document.querySelector("#submit-run");
const downloadButton = document.querySelector("#download-report");
const refreshReserveButton = document.querySelector("#refresh-reserve");
const imageReservePanel = document.querySelector("#image-reserve");
const emptyState = document.querySelector("#empty-state");
const statusPanel = document.querySelector("#run-status");
const reportView = document.querySelector("#report-view");
const deleteBuildImageInput = document.querySelector("#delete-build-image");

let currentReport = null;
let currentRun = null;

providerInput.addEventListener("change", () => {
  const defaults = providerDefaults[providerInput.value] || providerDefaults.custom;
  baseUrlInput.value = defaults.baseUrl;
  modelInput.value = defaults.model;
  updateKeyDependentState();
});

apiKeyInput.addEventListener("input", updateKeyDependentState);

toggleKeyButton.addEventListener("click", () => {
  apiKeyInput.type = apiKeyInput.type === "password" ? "text" : "password";
});

refreshReserveButton.addEventListener("click", loadImageReserve);

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  if (!file) {
    fileTitle.textContent = "选择智能体压缩包";
    fileMeta.textContent = "仅支持 .zip 文件";
    return;
  }
  fileTitle.textContent = file.name;
  fileMeta.textContent = `${formatBytes(file.size)} · ${file.type || "application/zip"}`;
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = fileInput.files[0];
  if (!file) {
    setError("请先选择一个 .zip 压缩包。");
    return;
  }

  currentReport = null;
  currentRun = null;
  downloadButton.disabled = true;
  emptyState.classList.add("hidden");
  reportView.classList.add("hidden");
  statusPanel.classList.remove("hidden");
  statusPanel.innerHTML = "";
  submitButton.disabled = true;
  submitButton.textContent = "测试中";

  try {
    const payload = new FormData();
    payload.append("file", file);
    payload.append("runtime_network", document.querySelector("#runtime-network").value);
    payload.append("build_mode", document.querySelector("#build-mode").value);
    payload.append("cache_policy", "use");
    payload.append("delete_build_image_after_run", deleteBuildImageInput?.checked ? "true" : "false");

    const providers = buildProviders();
    if (providers.length > 0) {
      payload.append("providers", JSON.stringify(providers));
    }

    const runtimeEnv = buildRuntimeEnv();
    if (Object.keys(runtimeEnv).length > 0) {
      payload.append("runtime_env", JSON.stringify(runtimeEnv));
    }

    const response = await fetch("/api/runs", { method: "POST", body: payload });
    if (!response.ok) {
      throw new Error(await readError(response));
    }
    currentRun = await response.json();
    renderStatus(currentRun, []);
    await pollRun(currentRun.id);
  } catch (error) {
    setError(error.message || String(error));
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "开始测试";
    loadImageReserve();
  }
});

downloadButton.addEventListener("click", () => {
  if (!currentReport) {
    return;
  }
  const markdown = reportMarkdown(currentReport);
  const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `aegisagent-report-${currentReport.run_id || "run"}.md`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});

function updateKeyDependentState() {
  const hasProvider = providerInput.value !== "none";
  const hasKey = apiKeyInput.value.trim().length > 0;
  const enabled = hasProvider && hasKey;
  llmOptions.disabled = !enabled;
  noKeyWarning.classList.toggle("hidden", enabled);
  keyState.textContent = enabled ? "API KEY 已提供：******" : "未提供 API KEY";
  keyState.classList.toggle("ready", enabled);
}

function buildProviders() {
  const provider = providerInput.value;
  const apiKey = apiKeyInput.value.trim();
  const model = modelInput.value.trim();
  const baseUrl = baseUrlInput.value.trim();
  if (provider === "none" || !apiKey || !model) {
    return [];
  }

  const roles = [];
  if (document.querySelector("#llm-audit").checked) roles.push("audit");
  if (document.querySelector("#llm-build").checked) roles.push("build");
  if (document.querySelector("#llm-attack").checked) roles.push("attack");

  return roles.map((role) => ({
    provider: provider === "custom" ? "openai-compatible" : provider,
    base_url: baseUrl || null,
    api_key: apiKey,
    model,
    role,
  }));
}

function buildRuntimeEnv() {
  const provider = providerInput.value;
  const apiKey = apiKeyInput.value.trim();
  const model = modelInput.value.trim();
  const baseUrl = baseUrlInput.value.trim();
  if (provider === "none" || !apiKey) {
    return {};
  }
  const env = {
    LLM_API_KEY: apiKey,
    LLM_MODEL: model,
  };
  if (baseUrl) {
    env.LLM_BASE_URL = baseUrl;
    env.LLM_API_ENDPOINT = baseUrl;
  }
  if (provider === "openai" || provider === "custom") {
    env.OPENAI_API_KEY = apiKey;
    if (baseUrl) {
      env.OPENAI_BASE_URL = baseUrl;
      env.OPENAI_API_BASE_URL = baseUrl;
      env.OPENAI_API_ENDPOINT = baseUrl;
    }
    if (model) {
      env.OPENAI_MODEL_NAME = model;
      env.OPENAI_API_MODEL = model;
      env.MODEL_NAME = model;
    }
  }
  if (provider === "deepseek") {
    env.DEEPSEEK_API_KEY = apiKey;
    if (baseUrl) {
      env.DEEPSEEK_BASE_URL = baseUrl;
      env.DEEPSEEK_API_ENDPOINT = baseUrl;
    }
    if (model) {
      env.DEEPSEEK_MODEL = model;
      env.MODEL_NAME = model;
    }
  }
  if (provider === "siliconflow") {
    env.SILICONFLOW_API_KEY = apiKey;
    if (baseUrl) {
      env.SILICONFLOW_BASE_URL = baseUrl;
      env.SILICONFLOW_API_ENDPOINT = baseUrl;
    }
    if (model) {
      env.SILICONFLOW_MODEL = model;
      env.MODEL_NAME = model;
    }
  }
  return env;
}

async function pollRun(runId) {
  for (;;) {
    const [runResponse, eventsResponse] = await Promise.all([
      fetch(`/api/runs/${runId}`),
      fetch(`/api/runs/${runId}/events`),
    ]);
    if (!runResponse.ok) {
      throw new Error(await readError(runResponse));
    }
    const run = await runResponse.json();
    const events = eventsResponse.ok ? (await eventsResponse.json()).events || [] : [];
    currentRun = run;
    renderStatus(run, events);
    if (run.status === "completed" || run.status === "failed") {
      await loadReport(runId);
      return;
    }
    await sleep(1500);
  }
}

async function loadReport(runId) {
  const response = await fetch(`/api/runs/${runId}/report`);
  if (!response.ok) {
    throw new Error(await readError(response));
  }
  currentReport = await response.json();
  downloadButton.disabled = false;
  renderReport(currentReport);
}

async function loadImageReserve() {
  imageReservePanel.textContent = "正在读取本地镜像储备状态...";
  try {
    const response = await fetch("/api/image-reserve");
    if (!response.ok) {
      throw new Error(await readError(response));
    }
    renderImageReserve(await response.json());
  } catch (error) {
    imageReservePanel.innerHTML = `<div class="notice">无法读取镜像储备状态：${escapeHtml(error.message || String(error))}</div>`;
  }
}

function renderImageReserve(status) {
  const summary = status.summary || {};
  const languages = status.languages || {};
  const languageRows = Object.entries(languages)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, info]) => {
      const layer = info.selected_layer || "unknown";
      const selected = info.selected_image || "-";
      return `<tr><td>${escapeHtml(name)}</td><td>${escapeHtml(layerLabel(layer))}</td><td>${escapeHtml(selected)}</td></tr>`;
    })
    .join("");
  imageReservePanel.innerHTML = `
    <div class="reserve-grid">
      ${metric("增强镜像可用", summary.local_reserve_ready || 0)}
      ${metric("本地公共缓存", summary.cached_public_fallback_ready || 0)}
      ${metric("仍需公共拉取", summary.public_pull_required || 0)}
    </div>
    <table class="reserve-table">
      <thead><tr><th>语言层</th><th>命中层级</th><th>当前选择镜像</th></tr></thead>
      <tbody>${languageRows || `<tr><td colspan="3">暂无镜像策略数据</td></tr>`}</tbody>
    </table>
  `;
}

function renderStatus(run, events) {
  statusPanel.innerHTML = `
    <div class="status-grid">
      ${metric("状态", run.status)}
      ${metric("阶段", run.stage)}
      ${metric("动态测试", run.dynamic_status || "-")}
      ${metric("风险等级", riskLabel(run.risk_level || "-"))}
    </div>
    <div class="event-list">
      ${events.slice(-6).map((event) => `<div class="event-line">${escapeHtml(event.stage)} · ${escapeHtml(event.level)} · ${escapeHtml(event.message)}</div>`).join("")}
    </div>
  `;
}

function renderReport(report) {
  reportView.classList.remove("hidden");
  const markdown = reportMarkdown(report);
  reportView.innerHTML = `
    <div class="status-grid">
      ${metric("运行结果", report.status)}
      ${metric("动态状态", report.dynamic_status)}
      ${metric("LLM 状态", report.llm_status)}
      ${metric("构建状态", report.build_status || "-")}
    </div>
    <article class="markdown-report">
      ${renderMarkdown(markdown)}
    </article>
    <details class="raw-json">
      <summary>开发者调试信息</summary>
      <pre>${escapeHtml(JSON.stringify({ ...report, markdown_report: undefined }, null, 2))}</pre>
    </details>
  `;
}

function reportMarkdown(report) {
  return report.markdown_report || buildFallbackMarkdown(report);
}

function buildFallbackMarkdown(report) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const lines = [
    "# AegisAgent 智能体安全测试报告",
    "",
    "## 一、测试结论",
    "",
    `- 运行结果：${report.status || "-"}`,
    `- 动态测试：${report.dynamic_status || "-"}`,
    `- 风险等级：${riskLabel(report.risk_level || "-")}`,
    "",
    "## 二、给用户的建议",
    "",
    report.recommendation || "报告已生成。",
    "",
    "## 三、主要发现",
    "",
  ];
  if (!findings.length) {
    lines.push("未发现明确风险项。");
  } else {
    findings.forEach((finding, index) => {
      lines.push(`### ${index + 1}. ${finding.title || finding.category || "风险项"}`);
      lines.push("");
      lines.push(`- 严重性：${riskLabel(finding.severity || "info")}`);
      lines.push(`- 风险类型：${finding.risk_type || finding.source || "-"}`);
      lines.push("");
      lines.push(finding.description || "无详细描述。");
      lines.push("");
    });
  }
  return lines.join("\n");
}

function renderMarkdown(markdown) {
  const lines = markdown.split(/\r?\n/);
  const html = [];
  let inList = false;
  let inCode = false;
  const closeList = () => {
    if (inList) {
      html.push("</ul>");
      inList = false;
    }
  };

  for (const line of lines) {
    if (line.startsWith("```")) {
      closeList();
      html.push(inCode ? "</code></pre>" : "<pre><code>");
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      html.push(`${escapeHtml(line)}\n`);
      continue;
    }
    if (!line.trim()) {
      closeList();
      continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      closeList();
      const level = Math.min(heading[1].length + 1, 5);
      html.push(`<h${level}>${escapeHtml(heading[2])}</h${level}>`);
      continue;
    }
    if (line.startsWith("- ")) {
      if (!inList) {
        html.push("<ul>");
        inList = true;
      }
      html.push(`<li>${inlineMarkdown(line.slice(2))}</li>`);
      continue;
    }
    if (line.startsWith("> ")) {
      closeList();
      html.push(`<blockquote>${inlineMarkdown(line.slice(2))}</blockquote>`);
      continue;
    }
    closeList();
    html.push(`<p>${inlineMarkdown(line)}</p>`);
  }
  closeList();
  if (inCode) {
    html.push("</code></pre>");
  }
  return html.join("");
}

function inlineMarkdown(value) {
  return escapeHtml(value).replace(/`([^`]+)`/g, "<code>$1</code>");
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value == null ? "-" : String(value))}</strong></div>`;
}

function riskLabel(value) {
  const labels = {
    critical: "严重",
    high: "高",
    medium: "中",
    low: "低",
    info: "提示",
    unknown: "未知",
  };
  return labels[String(value).toLowerCase()] || value;
}

function layerLabel(value) {
  const labels = {
    local_reserve: "增强镜像",
    cached_public_fallback: "本地公共缓存",
    public_fallback: "公共镜像源",
    public_pull_required: "需要拉取",
    requested_local: "请求镜像已缓存",
    requested_image: "请求镜像",
    sandbox_yaml_local: "sandbox.yaml 本地镜像",
    sandbox_yaml_mirror: "sandbox.yaml 镜像源",
    sandbox_yaml_declared: "sandbox.yaml 声明镜像",
    project_dockerfile: "项目 Dockerfile",
    missing_policy: "缺少策略",
  };
  return labels[String(value)] || value;
}

function setError(message) {
  emptyState.classList.add("hidden");
  statusPanel.classList.remove("hidden");
  statusPanel.innerHTML = `<div class="notice">${escapeHtml(message)}</div>`;
}

async function readError(response) {
  try {
    const data = await response.json();
    return data.detail || JSON.stringify(data);
  } catch {
    return `${response.status} ${response.statusText}`;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

updateKeyDependentState();
loadImageReserve();
