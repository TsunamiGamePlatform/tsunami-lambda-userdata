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
    logs.push(
      args.map((a) => (typeof a === "object" ? JSON.stringify(a) : a)).join(" ")
    );

  const route = event.rawPath || event.path;
  log("Route determined:", route);

  try {
    if (route.endsWith("/create-account"))
      return await handleCreateAccount(event, log, logs);
    if (route.endsWith("/login")) return await handleLogin(event, log, logs);
    if (route.endsWith("/get-account"))
      return await handleGetAccount(event, log, logs);
    if (route.endsWith("/get-config"))
      return await handleGetConfig(event, log, logs);
    if (route.endsWith("/save-config"))
      return await handleSaveConfig(event, log, logs);
    if (route.endsWith("/update-setting"))
      return await handleUpdateSetting(event, log, logs);
    if (route.endsWith("/rebuild-indexes"))
      return await handleRebuildIndexes(event, log, logs);
    return jsonResponse(
      404,
      "ERR_ROUTE_NOT_FOUND",
      "❌ Route not found",
      {},
      logs
    );
  } catch (err) {
    log("Lambda error:", err.message, err.stack);
    return jsonResponse(
      500,
      "ERR_SERVER",
      `❌ Server error: ${err.message}`,
      {},
      logs
    );
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
async function handleLogin(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(
      400,
      "ERR_INVALID_JSON",
      "❌ Invalid JSON body",
      {},
      logs
    );
  }

  const { username, password } = body;
  log("Fields received:", { username });
  if (!username || !password)
    return jsonResponse(
      400,
      "ERR_MISSING_FIELDS",
      "❌ Missing fields",
      {},
      logs
    );

  // Use username index for direct lookup
  const usernameKey = `users/by-username/${username.toLowerCase()}.json`;
  let userId;
  try {
    const usernameRes = await s3.send(
      new GetObjectCommand({ Bucket: BUCKET, Key: usernameKey })
    );
    const usernameJson = JSON.parse(await usernameRes.Body.transformToString());
    userId = usernameJson.userId;
  } catch (err) {
    log("❌ Username not found:", err.message);
    return jsonResponse(
      401,
      "ERR_INVALID_CREDENTIALS",
      "❌ Invalid username or password",
      {},
      logs
    );
  }

  // Fetch account file directly
  const accountKey = `users/${userId}/account.json`;
  try {
    const accountRes = await s3.send(
      new GetObjectCommand({ Bucket: BUCKET, Key: accountKey })
    );
    const accountJson = JSON.parse(await accountRes.Body.transformToString());
    const isMatch =
      accountJson.username === username &&
      (await bcrypt.compare(password, accountJson.password));
    if (!isMatch) {
      log("❌ Password mismatch");
      return jsonResponse(
        401,
        "ERR_INVALID_CREDENTIALS",
        "❌ Invalid username or password",
        {},
        logs
      );
    }

    // ✅ Ensure username/email indexes exist
    const emailKey = `users/by-email/${accountJson.email.toLowerCase()}.json`;
    const putIndexOps = [];

    // Check username index
    try {
      await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: usernameKey }));
    } catch (err) {
      if (err.name === "NoSuchKey") {
        putIndexOps.push(
          s3.send(
            new PutObjectCommand({
              Bucket: BUCKET,
              Key: usernameKey,
              Body: JSON.stringify({ userId }),
              ContentType: "application/json",
            })
          )
        );
        log("⚠️ Missing username index recreated");
      }
    }

    // Check email index
    try {
      await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: emailKey }));
    } catch (err) {
      if (err.name === "NoSuchKey") {
        putIndexOps.push(
          s3.send(
            new PutObjectCommand({
              Bucket: BUCKET,
              Key: emailKey,
              Body: JSON.stringify({ userId }),
              ContentType: "application/json",
            })
          )
        );
        log("⚠️ Missing email index recreated");
      }
    }

    if (putIndexOps.length) {
      await Promise.all(putIndexOps);
    }

    // Load config (if exists)
    let configJson = {};
    try {
      const configRes = await s3.send(
        new GetObjectCommand({
          Bucket: BUCKET,
          Key: `users/${userId}/config.json`,
        })
      );
      configJson = JSON.parse(await configRes.Body.transformToString());
    } catch (err) {
      log("⚠️ Config load failed, returning empty config:", err.message);
    }

    const token = jwt.sign({ userId, username }, JWT_SECRET, {
      expiresIn: JWT_EXPIRY,
    });
    return jsonResponse(
      200,
      "SUCCESS_LOGIN",
      "✅ Login successful",
      { token, config: configJson },
      logs
    );
  } catch (err) {
    log("❌ Account file error:", err.message);
    return jsonResponse(
      401,
      "ERR_INVALID_CREDENTIALS",
      "❌ Invalid username or password",
      {},
      logs
    );
  }
}

// --- GET ACCOUNT ---
async function handleGetAccount(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(
      400,
      "ERR_INVALID_JSON",
      "❌ Invalid JSON body",
      {},
      logs
    );
  }

  let userId;
  try {
    userId = verifyToken(body, log);
  } catch (err) {
    return jsonResponse(
      401,
      "ERR_NOT_LOGGED_IN",
      `❌ Unauthorized: ${err.message}`,
      {},
      logs
    );
  }

  if (!userId)
    return jsonResponse(
      400,
      "ERR_MISSING_FIELDS",
      "❌ Missing userId",
      {},
      logs
    );

  try {
    const res = await s3.send(
      new GetObjectCommand({
        Bucket: BUCKET,
        Key: `users/${userId}/account.json`,
      })
    );
    const raw = await res.Body.transformToString();
    const account = JSON.parse(raw);
    const { password, ...safeAccount } = account;
    return jsonResponse(
      200,
      "SUCCESS_GET_ACCOUNT",
      "✅ Account fetched",
      { account: safeAccount },
      logs
    );
  } catch (err) {
    log("❌ Failed to load account:", err.message);
    return jsonResponse(
      404,
      "ERR_ACCOUNT_NOT_FOUND",
      "❌ Account not found",
      {},
      logs
    );
  }
}
// --- REBUILD INDEXES ---
async function handleRebuildIndexes(event, log, logs) {
  try {
    let ContinuationToken = undefined;
    let rebuilt = 0;
    let skipped = 0;

    do {
      const listRes = await s3.send(
        new ListObjectsV2Command({
          Bucket: BUCKET,
          Prefix: "users/",
          ContinuationToken,
        })
      );

      const accountKeys = (listRes.Contents || [])
        .map((obj) => obj.Key)
        .filter((k) => k.endsWith("account.json"));

      for (const key of accountKeys) {
        const userId = key.split("/")[1]; // users/<uuid>/account.json
        try {
          const accountRes = await s3.send(
            new GetObjectCommand({ Bucket: BUCKET, Key: key })
          );
          const accountJson = JSON.parse(
            await accountRes.Body.transformToString()
          );

          const usernameKey = `users/by-username/${accountJson.username.toLowerCase()}.json`;
          const emailKey = `users/by-email/${accountJson.email.toLowerCase()}.json`;

          let needUsername = false;
          let needEmail = false;

          try {
            await s3.send(
              new GetObjectCommand({ Bucket: BUCKET, Key: usernameKey })
            );
          } catch (err) {
            if (err.name === "NoSuchKey") needUsername = true;
          }

          try {
            await s3.send(
              new GetObjectCommand({ Bucket: BUCKET, Key: emailKey })
            );
          } catch (err) {
            if (err.name === "NoSuchKey") needEmail = true;
          }

          const ops = [];
          if (needUsername) {
            ops.push(
              s3.send(
                new PutObjectCommand({
                  Bucket: BUCKET,
                  Key: usernameKey,
                  Body: JSON.stringify({ userId }),
                  ContentType: "application/json",
                })
              )
            );
          }
          if (needEmail) {
            ops.push(
              s3.send(
                new PutObjectCommand({
                  Bucket: BUCKET,
                  Key: emailKey,
                  Body: JSON.stringify({ userId }),
                  ContentType: "application/json",
                })
              )
            );
          }

          if (ops.length) {
            await Promise.all(ops);
            rebuilt++;
            log(`Rebuilt index for userId=${userId}`);
          } else {
            skipped++;
          }
        } catch (err) {
          log("❌ Failed processing account:", key, err.message);
        }
      }

      ContinuationToken = listRes.IsTruncated
        ? listRes.NextContinuationToken
        : undefined;
    } while (ContinuationToken);

    return jsonResponse(
      200,
      "SUCCESS_REBUILD_INDEXES",
      "✅ Index rebuild complete",
      { rebuilt, skipped },
      logs
    );
  } catch (err) {
    log("❌ Rebuild failed:", err.message);
    return jsonResponse(
      500,
      "ERR_REBUILD_FAILED",
      `❌ Rebuild failed: ${err.message}`,
      {},
      logs
    );
  }
}
// --- GET CONFIG ---
async function handleGetConfig(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(
      400,
      "ERR_INVALID_JSON",
      "❌ Invalid JSON body",
      {},
      logs
    );
  }

  let userId;
  try {
    userId = verifyToken(body, log);
  } catch (err) {
    return jsonResponse(
      401,
      "ERR_NOT_LOGGED_IN",
      `❌ Unauthorized: ${err.message}`,
      {},
      logs
    );
  }

  if (!userId)
    return jsonResponse(
      400,
      "ERR_MISSING_FIELDS",
      "❌ Missing userId",
      {},
      logs
    );

  try {
    const res = await s3.send(
      new GetObjectCommand({
        Bucket: BUCKET,
        Key: `users/${userId}/config.json`,
      })
    );
    const raw = await res.Body.transformToString();
    const config = JSON.parse(raw);
    return jsonResponse(
      200,
      "SUCCESS_GET_CONFIG",
      "✅ Config fetched",
      { config },
      logs
    );
  } catch (err) {
    log("❌ Failed to load config:", err.message);
    return jsonResponse(
      404,
      "ERR_CONFIG_NOT_FOUND",
      "❌ Config not found",
      {},
      logs
    );
  }
}

// --- SAVE CONFIG ---
async function handleSaveConfig(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(
      400,
      "ERR_INVALID_JSON",
      "❌ Invalid JSON body",
      {},
      logs
    );
  }

  const { config, token } = body;
  let userId;
  try {
    userId = verifyToken(body, log);
  } catch (err) {
    return jsonResponse(
      401,
      "ERR_NOT_LOGGED_IN",
      `❌ Unauthorized: ${err.message}`,
      {},
      logs
    );
  }

  if (!userId || !config)
    return jsonResponse(
      400,
      "ERR_MISSING_FIELDS",
      "❌ Missing fields",
      {},
      logs
    );

  try {
    await s3.send(
      new PutObjectCommand({
        Bucket: BUCKET,
        Key: `users/${userId}/config.json`,
        Body: JSON.stringify(config, null, 2),
        ContentType: "application/json",
      })
    );
    return jsonResponse(
      200,
      "SUCCESS_SAVE_CONFIG",
      "✅ Config saved",
      { config },
      logs
    );
  } catch (err) {
    log("❌ Failed to save config:", err.message);
    return jsonResponse(
      500,
      "ERR_S3_UPLOAD",
      "❌ Failed to save config",
      {},
      logs
    );
  }
}

// --- UPDATE SETTING ---
async function handleUpdateSetting(event, log, logs) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    log("❌ JSON parse error:", err.message);
    return jsonResponse(
      400,
      "ERR_INVALID_JSON",
      "❌ Invalid JSON body",
      {},
      logs
    );
  }

  const { key, value, token } = body;
  let userId;
  try {
    userId = jwt.verify(token, JWT_SECRET).userId;
  } catch (err) {
    log("❌ Invalid token:", err.message);
    return jsonResponse(
      401,
      "ERR_NOT_LOGGED_IN",
      `❌ Unauthorized: ${err.message}`,
      {},
      logs
    );
  }

  if (!userId || key === undefined || value === undefined)
    return jsonResponse(
      400,
      "ERR_MISSING_FIELDS",
      "❌ Missing fields",
      {},
      logs
    );

  try {
    const configRes = await s3.send(
      new GetObjectCommand({
        Bucket: BUCKET,
        Key: `users/${userId}/config.json`,
      })
    );
    const config = JSON.parse(await configRes.Body.transformToString());
    config[key] = value;

    await s3.send(
      new PutObjectCommand({
        Bucket: BUCKET,
        Key: `users/${userId}/config.json`,
        Body: JSON.stringify(config, null, 2),
        ContentType: "application/json",
      })
    );
    return jsonResponse(
      200,
      "SUCCESS_UPDATE_SETTING",
      "✅ Setting updated",
      { config },
      logs
    );
  } catch (err) {
    log("❌ Failed to update config:", err.message);
    return jsonResponse(500, "ERR_UPDATE_ERROR", "❌ Update error", {}, logs);
  }
}
