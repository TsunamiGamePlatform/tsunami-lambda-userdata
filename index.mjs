import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcryptjs";
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
} from "@aws-sdk/client-s3";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = "7d";

const s3 = new S3Client({ region: "us-east-1" });
const BUCKET = "click.accountdata";

export async function handler(event) {
  const logs = [];
  const log = (...args) =>
    logs.push(args.map((a) => (typeof a === "object" ? JSON.stringify(a) : a)).join(" "));

  const route = event.rawPath || event.path;
  log("Route determined:", route);

  try {
    if (route.endsWith("/create-account")) return await handleCreateAccount(event, log, logs);
    if (route.endsWith("/login")) return await handleLogin(event, log, logs);
    if (route.endsWith("/get-account")) return await handleGetAccount(event, log, logs);
    if (route.endsWith("/get-config")) return await handleGetConfig(event, log, logs);
    if (route.endsWith("/save-config")) return await handleSaveConfig(event, log, logs);
    if (route.endsWith("/update-setting")) return await handleUpdateSetting(event, log, logs);

    return jsonResponse(404, "ERR_ROUTE_NOT_FOUND", "❌ Route not found", {}, logs);
  } catch (err) {
    log("Lambda error:", err.message, err.stack);
    return jsonResponse(500, "ERR_SERVER", `❌ Server error: ${err.message}`, {}, logs);
  }
}

// --- Helper to return consistent structured responses ---
function jsonResponse(statusCode, status, message, data = {}, logs = []) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status, message, ...data, logs }),
  };
}

// --- Token verification helper ---
function verifyToken(body, log) {
  const { token } = body;
  if (!token) {
    log("❌ Missing token");
    throw new Error("Missing token");
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded.userId;
  } catch (err) {
    log("❌ Invalid token:", err.message);
    throw new Error("Invalid token");
  }
}

// --- CREATE ACCOUNT ---
async function handleCreateAccount(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(400, "ERR_INVALID_JSON", "❌ Invalid JSON body", {}, logs);
  }

  const { username, password, email, birthday } = body;
  log("Fields received:", { username, email, birthday });
  if (!username || !password || !email || !birthday)
    return jsonResponse(400, "ERR_MISSING_FIELDS", "❌ Missing fields", {}, logs);

  const userId = uuidv4();
  const folder = `users/${userId}/`;
  const hashedPassword = await bcrypt.hash(password, 10);
  const account = { username, password: hashedPassword, email, birthday };
  const config = { theme: "light", notifications: true };

  try {
    await Promise.all([
      s3.send(
        new PutObjectCommand({
          Bucket: BUCKET,
          Key: `${folder}account.json`,
          Body: JSON.stringify(account, null, 2),
          ContentType: "application/json",
        })
      ),
      s3.send(
        new PutObjectCommand({
          Bucket: BUCKET,
          Key: `${folder}config.json`,
          Body: JSON.stringify(config, null, 2),
          ContentType: "application/json",
        })
      ),
    ]);
    log("Account and config saved to S3");
  } catch (err) {
    log("❌ S3 upload failed:", err.message);
    return jsonResponse(500, "ERR_S3_UPLOAD", "❌ Failed to save account data", {}, logs);
  }

  return jsonResponse(200, "SUCCESS_CREATE_ACCOUNT", "✅ Account created", { userId }, logs);
}

// --- LOGIN ---
async function handleLogin(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(400, "ERR_INVALID_JSON", "❌ Invalid JSON body", {}, logs);
  }

  const { username, password } = body;
  log("Fields received:", { username });
  if (!username || !password) return jsonResponse(400, "ERR_MISSING_FIELDS", "❌ Missing fields", {}, logs);

  let list;
  try {
    list = await s3.send(
      new ListObjectsV2Command({
        Bucket: BUCKET,
        Prefix: "users/",
        Delimiter: "/",
      })
    );
    log("✅ S3 list success");
  } catch (err) {
    log("❌ S3 list failed:", err.message);
    return jsonResponse(500, "ERR_S3_LIST", "❌ Failed to list user folders", { debug: { error: err.message, bucket: BUCKET } }, logs);
  }

  for (const prefix of list.CommonPrefixes || []) {
    const userId = prefix.Prefix.split("/")[1];
    const accountKey = `${prefix.Prefix}account.json`;
    log(`Checking user: ${userId}`);

    try {
      const accountRes = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: accountKey }));
      const accountJson = JSON.parse(await accountRes.Body.transformToString());
      const isMatch = accountJson.username === username && (await bcrypt.compare(password, accountJson.password));

      if (isMatch) {
        log(`✅ User ${userId} password matched`);
        let configJson = {};
        try {
          const configRes = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: `${prefix.Prefix}config.json` }));
          configJson = JSON.parse(await configRes.Body.transformToString());
        } catch (err) {
          log("⚠️ Config load failed, returning empty config:", err.message);
        }

        const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
        return jsonResponse(200, "SUCCESS_LOGIN", "✅ Login successful", { token, config: configJson }, logs);
      }
    } catch (err) {
      log("⚠️ Skipping user due to malformed account file:", err.message);
    }
  }

  log("❌ No matching user found");
  return jsonResponse(401, "ERR_INVALID_CREDENTIALS", "❌ Invalid username or password", {}, logs);
}

// --- GET ACCOUNT ---
async function handleGetAccount(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(400, "ERR_INVALID_JSON", "❌ Invalid JSON body", {}, logs);
  }

  let userId;
  try {
    userId = verifyToken(body, log);
  } catch (err) {
    return jsonResponse(401, "ERR_NOT_LOGGED_IN", `❌ Unauthorized: ${err.message}`, {}, logs);
  }

  if (!userId) return jsonResponse(400, "ERR_MISSING_FIELDS", "❌ Missing userId", {}, logs);

  try {
    const res = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: `users/${userId}/account.json` }));
    const raw = await res.Body.transformToString();
    const account = JSON.parse(raw);
    const { password, ...safeAccount } = account;
    return jsonResponse(200, "SUCCESS_GET_ACCOUNT", "✅ Account fetched", { account: safeAccount }, logs);
  } catch (err) {
    log("❌ Failed to load account:", err.message);
    return jsonResponse(404, "ERR_ACCOUNT_NOT_FOUND", "❌ Account not found", {}, logs);
  }
}

// --- GET CONFIG ---
async function handleGetConfig(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(400, "ERR_INVALID_JSON", "❌ Invalid JSON body", {}, logs);
  }

  let userId;
  try {
    userId = verifyToken(body, log);
  } catch (err) {
    return jsonResponse(401, "ERR_NOT_LOGGED_IN", `❌ Unauthorized: ${err.message}`, {}, logs);
  }

  if (!userId) return jsonResponse(400, "ERR_MISSING_FIELDS", "❌ Missing userId", {}, logs);

  try {
    const res = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: `users/${userId}/config.json` }));
    const raw = await res.Body.transformToString();
    const config = JSON.parse(raw);
    return jsonResponse(200, "SUCCESS_GET_CONFIG", "✅ Config fetched", { config }, logs);
  } catch (err) {
    log("❌ Failed to load config:", err.message);
    return jsonResponse(404, "ERR_CONFIG_NOT_FOUND", "❌ Config not found", {}, logs);
  }
}

// --- SAVE CONFIG ---
async function handleSaveConfig(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(400, "ERR_INVALID_JSON", "❌ Invalid JSON body", {}, logs);
  }

  const { config, token } = body;
  let userId;
  try {
    userId = verifyToken(body, log);
  } catch (err) {
    return jsonResponse(401, "ERR_NOT_LOGGED_IN", `❌ Unauthorized: ${err.message}`, {}, logs);
  }

  if (!userId || !config) return jsonResponse(400, "ERR_MISSING_FIELDS", "❌ Missing fields", {}, logs);

  try {
    await s3.send(
      new PutObjectCommand({ Bucket: BUCKET, Key: `users/${userId}/config.json`, Body: JSON.stringify(config, null, 2), ContentType: "application/json" })
    );
    return jsonResponse(200, "SUCCESS_SAVE_CONFIG", "✅ Config saved", { config }, logs);
  } catch (err) {
    log("❌ Failed to save config:", err.message);
    return jsonResponse(500, "ERR_S3_UPLOAD", "❌ Failed to save config", {}, logs);
  }
}

// --- UPDATE SETTING ---
async function handleUpdateSetting(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(400, "ERR_INVALID_JSON", "❌ Invalid JSON body", {}, logs);
  }

  const { key, value, token } = body;
  let userId;
  try {
    userId = jwt.verify(token, JWT_SECRET).userId;
  } catch (err) {
    log("❌ Invalid token:", err.message);
    return jsonResponse(401, "ERR_NOT_LOGGED_IN", `❌ Unauthorized: ${err.message}`, {}, logs);
  }

  if (!userId || key === undefined || value === undefined) return jsonResponse(400, "ERR_MISSING_FIELDS", "❌ Missing fields", {}, logs);

  try {
    const configRes = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: `users/${userId}/config.json` }));
    const config = JSON.parse(await configRes.Body.transformToString());
    config[key] = value;

    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: `users/${userId}/config.json`, Body: JSON.stringify(config, null, 2), ContentType: "application/json" }));
    return jsonResponse(200, "SUCCESS_UPDATE_SETTING", "✅ Setting updated", { config }, logs);
  } catch (err) {
    log("❌ Failed to update config:", err.message);
    return jsonResponse(500, "ERR_UPDATE_ERROR", "❌ Update error", {}, logs);
  }
}
