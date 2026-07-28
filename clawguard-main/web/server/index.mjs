import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import cors from "cors";
import express from "express";
import { fileURLToPath } from "node:url";
import {
  getChinaDistribution,
  getExposureList,
  getExposureStats,
  getExposureTrend,
  getVersionTrend,
  getWorldDistribution,
} from "./services/exposureService.mjs";
import {
  getOpenclawRiskIssues,
  getOpenclawRiskOverview,
  triggerOpenclawRiskRefresh,
} from "./services/openclawRiskService.mjs";
import {
  getSecurityResearchOverview,
  getSecurityResearchPapers,
  triggerSecurityResearchRefresh,
} from "./services/securityResearchService.mjs";
import { getSkillIntelligenceOverview } from "./services/skillIntelligenceService.mjs";
import { searchSkills } from "./services/skillSearchService.mjs";
import {
  getSkillStaticScanStatus,
  runSkillStaticScan,
} from "./services/skillStaticScanApiService.mjs";
import {
  SandboxBusyError,
  getDynamicSandboxCapacity,
  runSkillDynamicSandbox,
} from "./services/skillDynamicSandboxService.mjs";
import {
  getCurrentUserFromRequest,
  loginUser,
  registerUser,
} from "./services/authService.mjs";
import * as fileAuthService from "./services/fileAuthService.mjs";
import {
  createInviteCode,
  disableInviteCode,
  getInviteUsageByCode,
  listInviteCodes,
  updateInviteCode,
} from "./services/inviteService.mjs";
import { prisma } from "./lib/prisma.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const distDir = path.join(projectRoot, "dist");
const indexHtmlPath = path.join(distDir, "index.html");
const hasBuiltFrontend = fs.existsSync(indexHtmlPath);
const useFileAuth = String(process.env.AUTH_STORAGE || "file").toLowerCase() !== "database";
const authService = useFileAuth
  ? fileAuthService
  : { getCurrentUserFromRequest, loginUser, registerUser };
const inviteService = useFileAuth
  ? fileAuthService
  : { createInviteCode, disableInviteCode, getInviteUsageByCode, listInviteCodes, updateInviteCode };

const app = express();
const port = Number(process.env.API_PORT || 8787);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: process.env.API_JSON_LIMIT || "75mb" }));

function formatPublicSkillError(error) {
  const raw = String(error?.message || "").trim();
  const lower = raw.toLowerCase();
  const looksGarbled = /�|锟|绋|瀹|æ|å|ä|Â|Ð|Ñ/.test(raw);
  if (lower.includes("请上传 zip") || lower.includes("填写可下载的 url") || lower.includes("no files")) {
    return "请先选择要检测的 Skill 文件或压缩包，或填写可直接下载的文件链接。";
  }
  if (lower.includes("does not define executable actions") || lower.includes("skill-actions")) {
    return "已找到 SKILL.md。该 Skill 没有显式 skill-actions，需要按 ClawGuard 动态沙箱的 LLM 运行时执行；请在高级设置中启用 LLM 辅助触发与运行时适配，并填写模型密钥后重试。";
  }
  if (lower.includes("llm_config.api_key") || lower.includes("api_key") || lower.includes("api key")) {
    return "ClawGuard 动态沙箱的 LLM 运行时需要模型密钥。请在 Skill 高级设置中填写智能分析密钥后重试。";
  }
  if (lower.includes("html page") || lower.includes("raw skill markdown")) {
    return "上传的 SKILL.md 看起来是网页 HTML，不是原始 Skill Markdown。请从 GitHub/网页中下载 Raw 原始文件，或上传完整 Skill 目录压缩包。";
  }
  if (lower.includes("元数据") || lower.includes("_meta.json") || lower.includes("skill.json")) {
    return "上传的压缩包只包含 Skill 元数据，没有包含 SKILL.md 正文。请上传完整 Skill 目录压缩包，或直接上传 SKILL.md 文件。";
  }
  if (lower.includes("skill.md")) {
    if (lower.includes("multiple") || lower.includes("多个")) {
      return "上传内容包含多个 SKILL.md。动态检测一次只支持一个 Skill，请拆分后重新上传。";
    }
    return "未在上传内容中找到 SKILL.md。请上传包含 SKILL.md 的完整技能目录压缩包，或直接上传 SKILL.md 文件。";
  }
  if (lower.includes("zip") || lower.includes("archive")) {
    return "上传的压缩包无法识别。请确认文件未损坏，并包含完整的 Skill 目录。";
  }
  if (looksGarbled) {
    return "检测任务未能启动。请确认上传的是有效 Skill 包后重试。";
  }
  return raw || "动态沙箱执行失败。";
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, now: new Date().toISOString(), authStorage: useFileAuth ? "file" : "database" });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const data = await authService.registerUser(req.body || {});
    res.json({ ok: true, ...data });
  } catch (error) {
    res.status(400).json({ ok: false, message: error.message || "注册失败。" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const data = await authService.loginUser(req.body || {});
    res.json({ ok: true, ...data });
  } catch (error) {
    res.status(400).json({ ok: false, message: error.message || "登录失败。" });
  }
});

app.post("/api/auth/logout", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/auth/me", async (req, res) => {
  const user = await authService.getCurrentUserFromRequest(req);
  if (!user) {
    res.status(401).json({ ok: false, message: "当前未登录或登录已失效。" });
    return;
  }

  res.json({ ok: true, user });
});

async function getAdminUserOrReply(req, res) {
  const user = await authService.getCurrentUserFromRequest(req);
  if (!user) {
    res.status(401).json({ ok: false, message: "请先登录。" });
    return null;
  }
  if (user.role !== "admin") {
    res.status(403).json({ ok: false, message: "当前账号没有管理员权限。" });
    return null;
  }
  return user;
}

app.get("/api/admin/invites", async (req, res) => {
  const user = await getAdminUserOrReply(req, res);
  if (!user) return;

  try {
    const invites = await inviteService.listInviteCodes();
    res.json({ ok: true, invites });
  } catch (error) {
    res.status(500).json({ ok: false, message: error.message || "获取邀请码失败。" });
  }
});

app.post("/api/admin/invites", async (req, res) => {
  const user = await getAdminUserOrReply(req, res);
  if (!user) return;

  try {
    const invite = await inviteService.createInviteCode({
      code: req.body?.code,
      maxUses: req.body?.maxUses || 1,
      expiresAt: req.body?.expiresAt || null,
      note: req.body?.note || "",
      createdBy: user.username || `user-${user.id}`,
    });
    res.json({ ok: true, invite });
  } catch (error) {
    res.status(400).json({ ok: false, message: error.message || "创建邀请码失败。" });
  }
});

app.patch("/api/admin/invites/:code", async (req, res) => {
  const user = await getAdminUserOrReply(req, res);
  if (!user) return;

  try {
    const invite = await inviteService.updateInviteCode(req.params.code, {
      maxUses: req.body?.maxUses,
      expiresAt: req.body?.expiresAt,
      note: req.body?.note,
      status: req.body?.status,
    });
    res.json({ ok: true, invite });
  } catch (error) {
    res.status(400).json({ ok: false, message: error.message || "更新邀请码失败。" });
  }
});

app.post("/api/admin/invites/:code/disable", async (req, res) => {
  const user = await getAdminUserOrReply(req, res);
  if (!user) return;

  try {
    const invite = await inviteService.disableInviteCode(req.params.code);
    res.json({ ok: true, invite });
  } catch (error) {
    res.status(400).json({ ok: false, message: error.message || "禁用邀请码失败。" });
  }
});

app.get("/api/admin/invites/:code/usage", async (req, res) => {
  const user = await getAdminUserOrReply(req, res);
  if (!user) return;

  try {
    const invite = await inviteService.getInviteUsageByCode(req.params.code);
    res.json({ ok: true, invite });
  } catch (error) {
    res.status(400).json({ ok: false, message: error.message || "获取使用记录失败。" });
  }
});

app.get("/api/exposure/stats", async (req, res) => {
  try {
    const data = await getExposureStats(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch stats." });
  }
});

app.get("/api/exposure/world-distribution", async (req, res) => {
  try {
    const data = await getWorldDistribution(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch world distribution." });
  }
});

app.get("/api/exposure/china-distribution", async (req, res) => {
  try {
    const data = await getChinaDistribution(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch china distribution." });
  }
});

app.get("/api/exposure/trend", async (req, res) => {
  try {
    const data = await getExposureTrend(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch trend." });
  }
});

app.get("/api/exposure/version-trend", async (req, res) => {
  try {
    const data = await getVersionTrend(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch version trend." });
  }
});

app.get("/api/exposure/list", async (req, res) => {
  try {
    const data = await getExposureList(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch exposure list." });
  }
});

app.get("/api/openclaw-risk/overview", async (req, res) => {
  try {
    const data = await getOpenclawRiskOverview(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch OpenClaw risk overview." });
  }
});

app.get("/api/openclaw-risk/issues", async (req, res) => {
  try {
    const data = await getOpenclawRiskIssues(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch OpenClaw risk issues." });
  }
});

app.post("/api/openclaw-risk/refresh", async (_req, res) => {
  try {
    const data = await triggerOpenclawRiskRefresh("manual-api");
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to refresh OpenClaw risk data." });
  }
});

app.get("/api/security-research/overview", async (req, res) => {
  try {
    const data = await getSecurityResearchOverview(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch security research overview." });
  }
});

app.get("/api/security-research/papers", async (req, res) => {
  try {
    const data = await getSecurityResearchPapers(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch security research papers." });
  }
});

app.get("/api/skill/intelligence/overview", async (req, res) => {
  try {
    const data = await getSkillIntelligenceOverview(req.query);
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to fetch skill intelligence overview." });
  }
});

app.get("/api/skill/search", async (req, res) => {
  try {
    const data = await searchSkills(req.query.q, { limit: req.query.limit });
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to search skills." });
  }
});

app.post("/api/skill/scan", async (req, res) => {
  try {
    const data = await runSkillStaticScan(req.body || {});
    res.json(data);
  } catch (error) {
    res.status(500).json({
      ok: false,
      message: error?.message || "静态扫描执行失败。",
    });
  }
});

app.get("/api/skill/scan/status", (req, res) => {
  const scanId = String(req.query?.scanId || "").trim();
  const data = getSkillStaticScanStatus(scanId);
  if (!data) {
    res.status(404).json({ ok: false, message: "Scan result not found." });
    return;
  }

  res.json({ ok: true, ...data });
});

app.get("/api/skill/dynamic-sandbox/capacity", (_req, res) => {
  res.json({ ok: true, capacity: getDynamicSandboxCapacity() });
});

app.post("/api/skill/dynamic-sandbox", async (req, res) => {
  const user = await authService.getCurrentUserFromRequest(req);
  if (!user) {
    res.status(401).json({ ok: false, code: "LOGIN_REQUIRED", message: "请先登录后再使用动态沙箱检测。" });
    return;
  }

  try {
    const data = await runSkillDynamicSandbox(req.body);
    res.json({
      ...data,
      capacity: getDynamicSandboxCapacity(),
      warning: "恢复出的链条仅为可能攻击路径，风险等级仅供参考。",
    });
  } catch (error) {
    if (error instanceof SandboxBusyError || error?.statusCode === 429) {
      res.status(429).json({
        ok: false,
        code: "SANDBOX_BUSY",
        message: error.message || "动态沙箱繁忙，请稍后再试。",
        capacity: getDynamicSandboxCapacity(),
      });
      return;
    }

    res.status(500).json({
      ok: false,
      code: error?.code || "SANDBOX_FAILED",
      message: formatPublicSkillError(error),
      capacity: getDynamicSandboxCapacity(),
    });
  }
});

app.post("/api/security-research/refresh", async (_req, res) => {
  try {
    const data = await triggerSecurityResearchRefresh("manual-api");
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message || "Failed to refresh security research data." });
  }
});

if (hasBuiltFrontend) {
  app.use(express.static(distDir));

  app.get("/{*path}", (req, res, next) => {
    if (req.path.startsWith("/api/")) {
      next();
      return;
    }

    res.sendFile(indexHtmlPath);
  });
}

if (useFileAuth) {
  fileAuthService.ensureDefaultAdmin()
    .then((user) => {
      if (user) {
        console.log(`[auth] file auth admin ready: ${user.username}`);
      }
    })
    .catch((error) => {
      console.error(`[auth] failed to prepare file auth admin: ${error.message || error}`);
    });
}

app.listen(port, () => {
  console.log(
    `[exposure-api] listening on http://127.0.0.1:${port}${hasBuiltFrontend ? " with built frontend" : ""} (${useFileAuth ? "file auth" : "database auth"})`
  );
});

process.on("SIGINT", async () => {
  await prisma.$disconnect();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  await prisma.$disconnect();
  process.exit(0);
});
