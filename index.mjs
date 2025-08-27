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
function sanitizeHtml(html) {
  // Remove all HTML tags
  html = html.replace(/<[^>]*>/g, "");

  // Remove special characters
  html = html.replace(/[<>\"\'&]/g, "");

  // Trim whitespace
  html = html.trim();

  // Limit length (optional, adjust as needed)
  html = html.slice(0, 100); // Limit to 100 characters

  return html;
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

  // Sanitize all inputs
  const sanitizedUsername = sanitizeHtml(username);
  const sanitizedPassword = sanitizeHtml(password);
  const sanitizedEmail = sanitizeHtml(email);
  const sanitizedBirthday = sanitizeHtml(birthday);

  if (
    !sanitizedUsername ||
    !sanitizedPassword ||
    !sanitizedEmail ||
    !sanitizedBirthday
  )
    return jsonResponse(
      400,
      "ERR_MISSING_FIELDS",
      "❌ Missing fields",
      {},
      logs
    );

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

  // Sanitize inputs
  const sanitizedUsername = sanitizeHtml(username);

  if (!sanitizedUsername || !password)
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
async function rebuildIndexes() {
  console.log("Rebuilding indexes...");
  const db = await getDatabaseConnection();

  // Get all users from the database
  const allUsers = await db.query("SELECT * FROM users");

  // Create a set of user IDs from the database
  const dbUserIds = new Set(allUsers.map((user) => user.id));

  // Get all indexed users (this is where we'll compare)
  const indexedUsers = await db.query(
    "SELECT id, username, email, password_hash, birthday FROM indexed_users"
  );

  // Create a set of user IDs from indexed users
  const indexedUserIds = new Set(indexedUsers.map((user) => user.id));

  // Find users that exist in the database but not in indexed_users
  const usersToAdd = allUsers.filter((user) => !indexedUserIds.has(user.id));

  // Find users that exist in indexed_users but not in the database
  const usersToRemove = indexedUsers.filter((user) => !dbUserIds.has(user.id));

  console.log(`Found ${usersToAdd.length} users to add`);
  console.log(`Found ${usersToRemove.length} users to remove`);

  if (usersToAdd.length > 0 || usersToRemove.length > 0) {
    await db.transaction(async (trx) => {
      // Add new users
      for (const user of usersToAdd) {
        await trx("indexed_users")
          .insert({
            id: user.id,
            username: user.username,
            email: user.email,
            password_hash: user.password_hash,
            birthday: user.birthday,
          })
          .onConflict((conflict) => {
            conflict.column("id").doUpdateSet({
              username: user.username,
              email: user.email,
              password_hash: user.password_hash,
              birthday: user.birthday,
            });
          });
      }

      // Remove old users
      for (const user of usersToRemove) {
        await trx("indexed_users").delete().where({ id: user.id });
      }
    });

    console.log("Indexes rebuilt successfully");
  } else {
    console.log("No changes needed in indexes");
  }

  // Update the last rebuild timestamp
  await db.query("UPDATE system SET last_rebuild = CURRENT_TIMESTAMP");

  process.exit(0);
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

  // Sanitize inputs
  const sanitizedKey = sanitizeHtml(key);
  const sanitizedValue = sanitizeHtml(value);

  if (sanitizedKey !== key || sanitizedValue !== value) {
    log("⚠️ Input sanitization warning:", {
      original: { key, value },
      sanitized: { sanitizedKey, sanitizedValue },
    });
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
