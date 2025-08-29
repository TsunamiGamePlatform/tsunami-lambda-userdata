import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcryptjs";
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  DeleteObjectsCommand,
} from "@aws-sdk/client-s3";
import jwt from "jsonwebtoken";
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = "7d";

const s3 = new S3Client({ region: "us-east-1" });
const BUCKET = "click.accountdata";
function sanitizeUsername(username) {
  // Only allow letters, numbers, and selected safe symbols
  const dirtyRegex = /[^A-Za-z0-9\-_.!$*+]/g;
  return dirtyRegex.test(username); // true = dirty/invalid
}
function sanitizePassword(password) {
  // Allow letters, numbers, and common password symbols
  const dirtyRegex = /[^A-Za-z0-9!$%^&*()\-_=+|;.\]]/g;
  return dirtyRegex.test(password); // true = dirty/invalid
}
function sanitizeSetting(input) {
  const dirtyRegex = /[^a-z]/g; // anything not a-z is invalid
  return dirtyRegex.test(input); // true = dirty/invalid
}
function sanitizeBirthday(birthday) {
  // Check ISO format first
  const isoRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!isoRegex.test(birthday)) return true; // invalid

  const [yearStr, monthStr, dayStr] = birthday.split("-");
  const year = Number(yearStr);
  const month = Number(monthStr) - 1; // JS months 0-11
  const day = Number(dayStr);

  const date = new Date(year, month, day);
  // Check if date matches input (avoids JS auto-correction like Feb 30 -> Mar 2)
  if (
    date.getFullYear() !== year ||
    date.getMonth() !== month ||
    date.getDate() !== day
  ) {
    return true; // invalid
  }

  return false; // clean
}
function sanitizeEmail(email) {
  const dirtyRegex = /[^A-Za-z0-9.@_-]/g; // allow letters, digits, dot, @, underscore, hyphen
  return dirtyRegex.test(email); // true = invalid
}
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
async function handleCreateAccount(event, log, logs) {
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

  const { username, password, email, birthday } = body;
  log("Fields received:", { username, email, birthday });

  if (!username || !password || !email || !birthday) {
    return jsonResponse(
      400,
      "ERR_MISSING_FIELDS",
      "❌ Required fields are missing",
      {},
      logs
    );
  }

  if (
    sanitizeUsername(username) ||
    sanitizePassword(password) ||
    sanitizeEmail(email) ||
    sanitizeBirthday(birthday)
  ) {
    return jsonResponse(
      400,
      "ERR_INVALID_FIELDS",
      "❌ Invalid characters in one or more fields",
      {},
      logs
    );
  }
  // === Age Check ===
  const minAge = 10; // minimum allowed age
  const birthDate = new Date(birthday);
  const age = Math.floor(
    (Date.now() - birthDate.getTime()) / (1000 * 60 * 60 * 24 * 365.25)
  );

  if (age < minAge) {
    return jsonResponse(
      400,
      "ERR_TOO_YOUNG",
      `❌ You must be at least ${minAge} years old to register`,
      {},
      logs
    );
  }
  // Check for duplicate username/email using S3 index files
  const usernameKey = `users/by-username/${username.toLowerCase()}.json`;
  const emailKey = `users/by-email/${email.toLowerCase()}.json`;
  let duplicateField = null;
  const [usernameCheck, emailCheck] = await Promise.allSettled([
    s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: usernameKey })),
    s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: emailKey })),
  ]);

  if (usernameCheck.status === "fulfilled") duplicateField = "username";
  if (emailCheck.status === "fulfilled")
    duplicateField = duplicateField || "email";

  if (
    (usernameCheck.status === "rejected" &&
      usernameCheck.reason.name !== "NoSuchKey") ||
    (emailCheck.status === "rejected" && emailCheck.reason.name !== "NoSuchKey")
  ) {
    log("❌ S3 error during index check:", {
      usernameError: usernameCheck.reason?.message,
      emailError: emailCheck.reason?.message,
    });
    return jsonResponse(500, "ERR_S3", "❌ S3 error", {}, logs);
  }

  if (duplicateField) {
    log(`❌ Duplicate ${duplicateField}`);
    return jsonResponse(
      409,
      "ERR_DUPLICATE_FIELD",
      `❌ Duplicate ${duplicateField}`,
      { duplicateField },
      logs
    );
  }

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
      // Write username and email index files for fast lookup
      s3.send(
        new PutObjectCommand({
          Bucket: BUCKET,
          Key: usernameKey,
          Body: JSON.stringify({ userId }),
          ContentType: "application/json",
        })
      ),
      s3.send(
        new PutObjectCommand({
          Bucket: BUCKET,
          Key: emailKey,
          Body: JSON.stringify({ userId }),
          ContentType: "application/json",
        })
      ),
    ]);
    log("Account, config, and indexes saved to S3");
  } catch (err) {
    log("❌ S3 upload failed:", err.message);
    return jsonResponse(
      500,
      "ERR_S3_UPLOAD",
      "❌ Failed to save account data",
      {},
      logs
    );
  }

  return jsonResponse(
    200,
    "SUCCESS_CREATE_ACCOUNT",
    "✅ Account created",
    { userId },
    logs
  );
}

// --- LOGIN ---
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

  // Check for missing fields
  if (!username || !password) {
    return jsonResponse(
      400,
      "ERR_MISSING_FIELDS",
      "❌ Missing fields",
      {},
      logs
    );
  }

  // Check for invalid characters
  if (sanitizeUsername(username) || sanitizePassword(password)) {
    return jsonResponse(
      400,
      "ERR_INVALID_FIELDS",
      "❌ Invalid characters in username or password",
      {},
      logs
    );
  }
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
    const accountDetails = {
      username: accountJson.username,
      email: accountJson.email,
      birthday: accountJson.birthday,
    };
    return jsonResponse(
      200,
      "SUCCESS_LOGIN",
      "✅ Login successful",
      { token, config: configJson, accountDetails },
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
    // === Step 0: Clear all existing username/email indexes ===
    const indexPrefixes = ["users/by-username/", "users/by-email/"];
    for (const prefix of indexPrefixes) {
      let ContinuationToken = undefined;
      do {
        const listRes = await s3.send(
          new ListObjectsV2Command({
            Bucket: BUCKET,
            Prefix: prefix,
            ContinuationToken,
          })
        );

        const keysToDelete = (listRes.Contents || []).map((obj) => ({
          Key: obj.Key,
        }));
        if (keysToDelete.length) {
          await s3.send(
            new DeleteObjectsCommand({
              Bucket: BUCKET,
              Delete: { Objects: keysToDelete },
            })
          );
          log(`Cleared ${keysToDelete.length} objects from ${prefix}`);
        }

        ContinuationToken = listRes.IsTruncated
          ? listRes.NextContinuationToken
          : undefined;
      } while (ContinuationToken);
    }

    // === Step 1: Rebuild indexes from actual accounts ===
    let ContinuationToken = undefined;
    let rebuilt = 0;

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
        try {
          const userId = key.split("/")[1]; // users/<uuid>/account.json
          const accountRes = await s3.send(
            new GetObjectCommand({ Bucket: BUCKET, Key: key })
          );
          const accountJson = JSON.parse(
            await accountRes.Body.transformToString()
          );

          const ops = [];

          const usernameKey = `users/by-username/${accountJson.username.toLowerCase()}.json`;
          const emailKey = `users/by-email/${accountJson.email.toLowerCase()}.json`;

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

          await Promise.all(ops);
          rebuilt++;
          log(`Rebuilt index for userId=${userId}`);
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
      { rebuilt },
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

  if (sanitizeSetting(key) || sanitizeSetting(value)) {
    return jsonResponse(
      400,
      "ERR_INVALID_FIELDS",
      "❌ Invalid input fields",
      {},
      logs
    );
  }

  try {
    const configRes = await s3.send(
      new GetObjectCommand({
        Bucket: BUCKET,
        Key: `users/${userId}/config.json`,
      })
    );
    const config = JSON.parse(await configRes.Body.transformToString());
    config[sanitizedKey] = sanitizedValue;

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
