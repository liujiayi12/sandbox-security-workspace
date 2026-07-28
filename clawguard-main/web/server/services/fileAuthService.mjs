import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  getBearerTokenFromRequest,
  hashPassword,
  normalizePhone,
  normalizeUsername,
  sanitizeUser,
  signAuthToken,
  validatePassword,
  validatePhone,
  validateUsername,
  verifyAuthToken,
  verifyPassword,
} from "../lib/auth.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "../..");
const defaultStorePath = path.resolve(projectRoot, "../runtime-cache/sandbox-auth-store.json");
const storePath = path.resolve(process.env.SANDBOX_AUTH_STORE || defaultStorePath);

function emptyStore() {
  return {
    nextUserId: 1,
    nextInviteId: 1,
    nextUsageId: 1,
    users: [],
    invites: [],
    usages: [],
  };
}

async function readStore() {
  try {
    const text = await fs.readFile(storePath, "utf8");
    return { ...emptyStore(), ...JSON.parse(text) };
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    const store = emptyStore();
    await writeStore(store);
    return store;
  }
}

async function writeStore(store) {
  await fs.mkdir(path.dirname(storePath), { recursive: true });
  await fs.writeFile(storePath, `${JSON.stringify(store, null, 2)}\n`, "utf8");
}

function normalizeInviteCode(code) {
  return String(code ?? "").trim().toUpperCase();
}

function normalizeStatus(status) {
  return status === "disabled" ? "disabled" : "active";
}

function parseOptionalDate(value) {
  if (value === undefined || value === null || value === "") return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error("expiresAt 不是合法日期。");
  }
  return date.toISOString();
}

function assertInviteCode(code) {
  if (!code) throw new Error("邀请码不能为空。");
  if (!/^[A-Z0-9_-]{4,128}$/.test(code)) {
    throw new Error("邀请码只能包含大写字母、数字、下划线或中划线，长度 4-128。");
  }
}

function assertMaxUses(maxUses) {
  if (!Number.isInteger(maxUses) || maxUses <= 0) {
    throw new Error("maxUses 必须是大于 0 的整数。");
  }
}

function publicInvite(invite) {
  return { ...invite };
}

function publicUser(user) {
  return sanitizeUser(user);
}

export function generateInviteCode(length = 12) {
  const raw = crypto.randomBytes(Math.max(8, length))
    .toString("base64")
    .replace(/[^A-Z0-9]/gi, "")
    .toUpperCase();
  return `SC-${raw.slice(0, Math.max(8, length))}`;
}

export async function ensureDefaultAdmin() {
  const password = String(process.env.DEFAULT_ADMIN_PASSWORD || process.env.SANDBOX_ADMIN_PASSWORD || "").trim();
  if (!password) return null;

  const username = normalizeUsername(process.env.DEFAULT_ADMIN_USERNAME || process.env.SANDBOX_ADMIN_USERNAME || "admin");
  const phone = normalizePhone(process.env.DEFAULT_ADMIN_PHONE || process.env.SANDBOX_ADMIN_PHONE || "13800000000");
  validateUsername(username);
  validatePassword(password);
  validatePhone(phone);

  const store = await readStore();
  const now = new Date().toISOString();
  const existing = store.users.find((user) => user.username === username);
  if (existing) {
    existing.passwordHash = hashPassword(password);
    existing.phone = phone;
    existing.role = "admin";
    existing.status = "active";
    existing.updatedAt = now;
    await writeStore(store);
    return publicUser(existing);
  }

  const user = {
    id: store.nextUserId++,
    username,
    phone,
    passwordHash: hashPassword(password),
    role: "admin",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  store.users.push(user);
  await writeStore(store);
  return publicUser(user);
}

export async function registerUser({ username, password, phone, inviteCode }) {
  const normalizedUsername = normalizeUsername(username);
  const normalizedPhone = normalizePhone(phone);
  const normalizedInviteCode = normalizeInviteCode(inviteCode);
  const normalizedPassword = String(password ?? "");

  if (!normalizedUsername || !normalizedPassword) throw new Error("用户名和密码不能为空。");
  if (!normalizedPhone) throw new Error("手机号不能为空。");
  if (!normalizedInviteCode) throw new Error("邀请码不能为空。");

  validateUsername(normalizedUsername);
  validatePassword(normalizedPassword);
  validatePhone(normalizedPhone);

  const store = await readStore();
  if (store.users.some((user) => user.username === normalizedUsername)) {
    throw new Error("该用户名已存在。");
  }
  if (store.users.some((user) => user.phone === normalizedPhone)) {
    throw new Error("该手机号已被注册。");
  }

  const invite = store.invites.find((item) => item.code === normalizedInviteCode);
  assertInviteAvailable(invite);

  const now = new Date().toISOString();
  const user = {
    id: store.nextUserId++,
    username: normalizedUsername,
    passwordHash: hashPassword(normalizedPassword),
    phone: normalizedPhone,
    role: "user",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  store.users.push(user);
  invite.usedCount += 1;
  invite.updatedAt = now;
  store.usages.push({
    id: store.nextUsageId++,
    inviteCodeId: invite.id,
    userId: user.id,
    usedAt: now,
  });
  await writeStore(store);

  const safeUser = publicUser(user);
  return { user: safeUser, token: signAuthToken(safeUser) };
}

export async function loginUser({ username, password }) {
  const normalizedUsername = normalizeUsername(username);
  const normalizedPassword = String(password ?? "");
  if (!normalizedUsername || !normalizedPassword) throw new Error("用户名和密码不能为空。");

  const store = await readStore();
  const user = store.users.find((item) => item.username === normalizedUsername);
  if (!user || !verifyPassword(normalizedPassword, user.passwordHash)) {
    throw new Error("账号或密码错误。");
  }
  if (user.status !== "active") throw new Error("当前账号已被禁用。");

  const safeUser = publicUser(user);
  return { user: safeUser, token: signAuthToken(safeUser) };
}

export async function getCurrentUserFromToken(token) {
  const payload = verifyAuthToken(token);
  const store = await readStore();
  const user = store.users.find((item) => item.id === Number(payload.sub));
  if (!user || user.status !== "active") throw new Error("当前登录已失效。");
  return publicUser(user);
}

export async function getCurrentUserFromRequest(req) {
  const token = getBearerTokenFromRequest(req);
  if (!token) return null;
  try {
    return await getCurrentUserFromToken(token);
  } catch {
    return null;
  }
}

export async function createInviteCode({
  code,
  maxUses = 1,
  expiresAt = null,
  note = "",
  createdBy = "",
} = {}) {
  const normalizedCode = normalizeInviteCode(code || generateInviteCode());
  assertInviteCode(normalizedCode);
  const cleanMaxUses = Number(maxUses);
  assertMaxUses(cleanMaxUses);
  const expiryDate = parseOptionalDate(expiresAt);

  const store = await readStore();
  if (store.invites.some((invite) => invite.code === normalizedCode)) {
    throw new Error("邀请码已存在。");
  }
  const now = new Date().toISOString();
  const invite = {
    id: store.nextInviteId++,
    code: normalizedCode,
    maxUses: cleanMaxUses,
    usedCount: 0,
    expiresAt: expiryDate,
    status: "active",
    note: String(note || "").trim() || null,
    createdBy: String(createdBy || "").trim() || null,
    createdAt: now,
    updatedAt: now,
  };
  store.invites.push(invite);
  await writeStore(store);
  return publicInvite(invite);
}

export async function listInviteCodes() {
  const store = await readStore();
  return store.invites
    .slice()
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
    .map(publicInvite);
}

export async function updateInviteCode(code, updates = {}) {
  const normalizedCode = normalizeInviteCode(code);
  if (!normalizedCode) throw new Error("邀请码不能为空。");

  const store = await readStore();
  const invite = store.invites.find((item) => item.code === normalizedCode);
  if (!invite) throw new Error("邀请码不存在。");

  if (updates.maxUses !== undefined) {
    const nextMaxUses = Number(updates.maxUses);
    assertMaxUses(nextMaxUses);
    invite.maxUses = nextMaxUses;
  }
  if (updates.expiresAt !== undefined) invite.expiresAt = parseOptionalDate(updates.expiresAt);
  if (updates.note !== undefined) invite.note = String(updates.note || "").trim() || null;
  if (updates.status !== undefined) invite.status = normalizeStatus(updates.status);
  invite.updatedAt = new Date().toISOString();
  await writeStore(store);
  return publicInvite(invite);
}

export async function disableInviteCode(code) {
  return updateInviteCode(code, { status: "disabled" });
}

export function assertInviteAvailable(inviteCode) {
  if (!inviteCode) throw new Error("邀请码不存在。");
  if (inviteCode.status !== "active") throw new Error("邀请码已被禁用。");
  if (inviteCode.expiresAt && new Date(inviteCode.expiresAt).getTime() < Date.now()) {
    throw new Error("邀请码已过期。");
  }
  if (inviteCode.usedCount >= inviteCode.maxUses) {
    throw new Error("邀请码使用次数已达上限。");
  }
}

export async function getInviteUsageByCode(code) {
  const normalizedCode = normalizeInviteCode(code);
  if (!normalizedCode) throw new Error("邀请码不能为空。");

  const store = await readStore();
  const invite = store.invites.find((item) => item.code === normalizedCode);
  if (!invite) throw new Error("邀请码不存在。");

  const usages = store.usages
    .filter((usage) => usage.inviteCodeId === invite.id)
    .sort((a, b) => String(b.usedAt).localeCompare(String(a.usedAt)))
    .map((usage) => ({
      ...usage,
      user: publicUser(store.users.find((user) => user.id === usage.userId) || {}),
    }));
  return { ...publicInvite(invite), usages };
}
