require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

console.log("DATABASE DIAGNOSTICS:", {
  hasDatabaseUrl: Boolean(process.env.DATABASE_URL),
  hasPublicUrl: Boolean(process.env.DATABASE_PUBLIC_URL),
  rentTest: process.env.RENT_TEST || "NOT FOUND",
  railwayService: process.env.RAILWAY_SERVICE_NAME || "unknown",
  railwayEnvironment: process.env.RAILWAY_ENVIRONMENT_NAME || "unknown",
  deploymentId: process.env.RAILWAY_DEPLOYMENT_ID || "unknown"
});

const allowedOrigins = [
  "https://iyaskobsp-spec.github.io",
  "http://localhost:5500",
  "http://127.0.0.1:5500"
];

app.set("trust proxy", 1);

app.use(helmet());

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error("Доступ із цього сайту заборонено"));
    }
  })
);

app.use(express.json({ limit: "1mb" }));

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl:
        process.env.NODE_ENV === "production"
          ? { rejectUnauthorized: false }
          : false
    })
  : null;

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "rent-admin-api"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "rent-admin-api"
  });
});

app.get("/api/db-health", async (req, res, next) => {
  try {
    if (!pool) {
      res.status(503).json({
        ok: false,
        error: "DATABASE_URL ще не підключено"
      });
      return;
    }

    const result = await pool.query("SELECT NOW() AS server_time");

    res.json({
      ok: true,
      database: "connected",
      serverTime: result.rows[0].server_time
    });
  } catch (error) {
    next(error);
  }
});


const rentCrypto = require("node:crypto");
const { promisify: rentPromisify } = require("node:util");
const rentScrypt = rentPromisify(rentCrypto.scrypt);

const RENT_SESSION_HOURS = 12;
const rentLoginAttempts = new Map();

async function hashRentPassword(password) {
  const salt = rentCrypto.randomBytes(16).toString("hex");
  const hash = await rentScrypt(password, salt, 64);
  return `scrypt:${salt}:${hash.toString("hex")}`;
}

async function verifyRentPassword(password, stored) {
  const parts = String(stored || "").split(":");

  if (parts.length !== 3 || parts[0] !== "scrypt") {
    return false;
  }

  const expected = Buffer.from(parts[2], "hex");

  if (expected.length !== 64) return false;

  const actual = await rentScrypt(password, parts[1], 64);

  return rentCrypto.timingSafeEqual(expected, actual);
}

function rentPublicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    mustChangePassword: user.must_change_password
  };
}

async function rentRequireSession(req, res, next) {
  try {
    const header = req.get("authorization") || "";
    const match = header.match(/^Bearer ([a-f0-9]{64})$/i);

    if (!match) {
      return res.status(401).json({
        ok: false,
        error: "Потрібно увійти в систему"
      });
    }

    const tokenHash = rentCrypto
      .createHash("sha256")
      .update(match[1])
      .digest("hex");

    const result = await pool.query(
      `SELECT
         s.id AS session_id,
         u.id, u.name, u.email, u.role,
         u.is_active, u.must_change_password
       FROM rent_user_sessions s
       JOIN rent_users u ON u.id = s.user_id
       WHERE s.token_hash = $1
         AND s.expires_at > NOW()
         AND s.session_version = u.session_version
         AND u.is_active = TRUE`,
      [tokenHash]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        ok: false,
        error: "Сесія завершена. Увійдіть повторно."
      });
    }

    req.rentUser = result.rows[0];
    next();
  } catch (error) {
    next(error);
  }
}

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body?.password || "");

    if (!email || !password || password.length > 1024) {
      return res.status(400).json({
        ok: false,
        error: "Вкажіть email і пароль"
      });
    }

    const attemptKey = `${req.ip}:${email}`;
    const now = Date.now();
    const attempt = rentLoginAttempts.get(attemptKey);

    if (attempt && attempt.until > now && attempt.count >= 5) {
      return res.status(429).json({
        ok: false,
        error: "Забагато спроб. Спробуйте через 15 хвилин."
      });
    }

    const result = await pool.query(
      `SELECT *
       FROM rent_users
       WHERE email = $1 AND is_active = TRUE`,
      [email]
    );

    const user = result.rows[0];

    const valid = user
      ? await verifyRentPassword(password, user.password_hash)
      : false;

    if (!valid) {
      const current = attempt && attempt.until > now
        ? attempt.count : 0;

      rentLoginAttempts.set(attemptKey, {
        count: current + 1,
        until: now + 15 * 60 * 1000
      });

      return res.status(401).json({
        ok: false,
        error: "Неправильний email або пароль"
      });
    }

    rentLoginAttempts.delete(attemptKey);

    const token = rentCrypto.randomBytes(32).toString("hex");
    const tokenHash = rentCrypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    await pool.query(
      `INSERT INTO rent_user_sessions
         (id, user_id, token_hash, expires_at, session_version)
       VALUES (
         $1, $2, $3,
         NOW() + INTERVAL '12 hours',
         $4
       )`,
      [
        rentCrypto.randomUUID(),
        user.id,
        tokenHash,
        user.session_version
      ]
    );

    res.json({
      ok: true,
      token,
      user: rentPublicUser(user)
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/auth/me", rentRequireSession, (req, res) => {
  res.json({
    ok: true,
    user: rentPublicUser(req.rentUser)
  });
});

app.post(
  "/api/auth/change-password",
  rentRequireSession,
  async (req, res, next) => {
    try {
      const currentPassword = String(
        req.body?.currentPassword || ""
      );

      const newPassword = String(
        req.body?.newPassword || ""
      );

      if (newPassword.length < 4 || newPassword.length > 1024) {
        return res.status(400).json({
          ok: false,
          error: "Пароль має містити мінімум 4 символи"
        });
      }

      const result = await pool.query(
        "SELECT password_hash FROM rent_users WHERE id = $1",
        [req.rentUser.id]
      );

      const valid = await verifyRentPassword(
        currentPassword,
        result.rows[0]?.password_hash
      );

      if (!valid) {
        return res.status(403).json({
          ok: false,
          error: "Поточний пароль неправильний"
        });
      }

      const hash = await hashRentPassword(newPassword);

      await pool.query(
        `UPDATE rent_users
         SET password_hash = $2,
             must_change_password = FALSE,
             session_version = session_version + 1
         WHERE id = $1`,
        [req.rentUser.id, hash]
      );

      res.json({
        ok: true,
        reloginRequired: true
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/auth/logout",
  rentRequireSession,
  async (req, res, next) => {
    try {
      await pool.query(
        "DELETE FROM rent_user_sessions WHERE id = $1",
        [req.rentUser.session_id]
      );

      res.json({ ok: true });
    } catch (error) {
      next(error);
    }
  }
);


function rentRequireAdmin(req, res, next) {
  if (req.rentUser.must_change_password) {
    return res.status(403).json({
      ok: false,
      error: "Спочатку змініть тимчасовий пароль"
    });
  }

  if (req.rentUser.role !== "admin") {
    return res.status(403).json({
      ok: false,
      error: "Доступ лише для адміністратора"
    });
  }

  next();
}

const rentAdminAccess = [rentRequireSession, rentRequireAdmin];

function rentUserDetails(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    isActive: user.is_active,
    mustChangePassword: user.must_change_password,
    createdAt: user.created_at
  };
}

function rentGenerateTempPassword() {
  const alphabet =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

  const bytes = rentCrypto.randomBytes(10);

  return [...bytes]
    .map(byte => alphabet[byte % alphabet.length])
    .join("");
}

app.get("/api/auth/users", ...rentAdminAccess, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT id, name, email, role, is_active,
             must_change_password, created_at
      FROM rent_users
      ORDER BY created_at DESC, id DESC
    `);

    res.json({
      ok: true,
      users: result.rows.map(rentUserDetails)
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/users", ...rentAdminAccess, async (req, res, next) => {
  try {
    const name = String(req.body?.name || "").trim();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const role = String(req.body?.role || "viewer");

    if (
      !name || name.length > 150 ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !["admin", "editor", "viewer"].includes(role)
    ) {
      return res.status(400).json({
        ok: false,
        error: "Перевірте ПІБ, email і роль користувача"
      });
    }

    const tempPassword = rentGenerateTempPassword();
    const passwordHash = await hashRentPassword(tempPassword);

    const result = await pool.query(
      `INSERT INTO rent_users (
         name, email, password_hash, role,
         is_active, must_change_password
       )
       VALUES ($1, $2, $3, $4, TRUE, TRUE)
       RETURNING id, name, email, role, is_active,
                 must_change_password, created_at`,
      [name, email, passwordHash, role]
    );

    res.status(201).json({
      ok: true,
      user: rentUserDetails(result.rows[0]),
      tempPassword
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        ok: false,
        error: "Користувач із таким email уже існує"
      });
    }

    next(error);
  }
});

app.patch("/api/auth/users/:id", ...rentAdminAccess, async (req, res, next) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний ID користувача"
    });
  }

  const name = req.body?.name;
  const role = req.body?.role;
  const active = req.body?.isActive;

  if (
    (name === undefined && role === undefined && active === undefined) ||
    (name !== undefined &&
      (typeof name !== "string" || !name.trim() || name.trim().length > 150)) ||
    (role !== undefined && !["admin", "editor", "viewer"].includes(role)) ||
    (active !== undefined && typeof active !== "boolean")
  ) {
    return res.status(400).json({
      ok: false,
      error: "Некоректні дані користувача"
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(
      "SELECT pg_advisory_xact_lock(731092, 2026)"
    );

    const found = await client.query(
      "SELECT * FROM rent_users WHERE id = $1 FOR UPDATE",
      [id]
    );

    if (!found.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        ok: false,
        error: "Користувача не знайдено"
      });
    }

    const user = found.rows[0];
    const nextRole = role === undefined ? user.role : role;
    const nextActive = active === undefined ? user.is_active : active;

    if (Number(user.id) === Number(req.rentUser.id) &&
        (nextRole !== "admin" || !nextActive)) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        ok: false,
        error: "Не можна заблокувати себе або зняти власні права адміністратора"
      });
    }

    if (user.role === "admin" && user.is_active &&
        (nextRole !== "admin" || !nextActive)) {
      const admins = await client.query(
        `SELECT COUNT(*)::integer AS total
         FROM rent_users
         WHERE role = 'admin' AND is_active = TRUE`
      );

      if (admins.rows[0].total <= 1) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          ok: false,
          error: "У системі має залишитися хоча б один активний адміністратор"
        });
      }
    }

    const result = await client.query(
      `UPDATE rent_users
       SET name = $2,
           role = $3,
           is_active = $4,
           session_version = session_version +
             CASE WHEN role IS DISTINCT FROM $3::text
                    OR is_active IS DISTINCT FROM $4::boolean
                  THEN 1 ELSE 0 END
       WHERE id = $1
       RETURNING id, name, email, role, is_active,
                 must_change_password, created_at`,
      [
        id,
        name === undefined ? user.name : name.trim(),
        nextRole,
        nextActive
      ]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      user: rentUserDetails(result.rows[0])
    });
  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

app.post(
  "/api/auth/users/:id/reset-password",
  ...rentAdminAccess,
  async (req, res, next) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({
        ok: false,
        error: "Некоректний ID користувача"
      });
    }

    try {
      const tempPassword = rentGenerateTempPassword();
      const hash = await hashRentPassword(tempPassword);

      const result = await pool.query(
        `UPDATE rent_users
         SET password_hash = $2,
             must_change_password = TRUE,
             session_version = session_version + 1
         WHERE id = $1
         RETURNING id`,
        [id, hash]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          error: "Користувача не знайдено"
        });
      }

      res.json({
        ok: true,
        tempPassword
      });
    } catch (error) {
      next(error);
    }
  }
);

app.delete(
  "/api/auth/users/:id",
  ...rentAdminAccess,
  async (req, res, next) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({
        ok: false,
        error: "Некоректний ID користувача"
      });
    }

    if (id === Number(req.rentUser.id)) {
      return res.status(400).json({
        ok: false,
        error: "Не можна видалити власний обліковий запис"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      await client.query(
        "SELECT pg_advisory_xact_lock(731092, 2026)"
      );

      const found = await client.query(
        "SELECT * FROM rent_users WHERE id = $1 FOR UPDATE",
        [id]
      );

      if (!found.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          ok: false,
          error: "Користувача не знайдено"
        });
      }

      const user = found.rows[0];

      if (user.role === "admin" && user.is_active) {
        const admins = await client.query(
          `SELECT COUNT(*)::integer AS total
           FROM rent_users
           WHERE role = 'admin' AND is_active = TRUE`
        );

        if (admins.rows[0].total <= 1) {
          await client.query("ROLLBACK");
          return res.status(400).json({
            ok: false,
            error: "Не можна видалити останнього активного адміністратора"
          });
        }
      }

      await client.query(
        "DELETE FROM rent_users WHERE id = $1",
        [id]
      );

      await client.query("COMMIT");

      res.json({ ok: true });
    } catch (error) {
      await client.query("ROLLBACK");
      next(error);
    } finally {
      client.release();
    }
  }
);

app.get("/api/contracts", async (req, res, next) => {
  try {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        error: "База даних не підключена"
      });
    }

    const archiveScope = req.query.scope === "archive";

    const result = await pool.query(`
      SELECT *
      FROM rent_contracts
      WHERE archived_at IS ${archiveScope ? "NOT NULL" : "NULL"}
      ORDER BY id ASC
    `);

    res.json({
      ok: true,
      total: result.rowCount,
      contracts: result.rows
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/contracts/import", express.json({ limit: "5mb" }), async (req, res, next) => {
  const importToken = process.env.RENT_IMPORT_TOKEN;
  const suppliedToken = req.get("x-import-token");

  if (!importToken) {
    return res.status(503).json({
      ok: false,
      error: "Ключ імпорту не налаштований"
    });
  }

  const crypto = require("node:crypto");
  const expected = Buffer.from(importToken);
  const received = Buffer.from(suppliedToken || "");

  if (
    expected.length !== received.length ||
    !crypto.timingSafeEqual(expected, received)
  ) {
    return res.status(403).json({
      ok: false,
      error: "Доступ до імпорту заборонено"
    });
  }

  if (!pool) {
    return res.status(503).json({
      ok: false,
      error: "База даних не підключена"
    });
  }

  const contracts = req.body?.contracts;

  if (
    !Array.isArray(contracts) ||
    contracts.length === 0 ||
    contracts.length > 500
  ) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний список договорів"
    });
  }

  const ids = new Set();

  for (const contract of contracts) {
    if (
      !contract ||
      typeof contract.id !== "string" ||
      !/^CTR-\d{4}$/.test(contract.id) ||
      ids.has(contract.id)
    ) {
      return res.status(400).json({
        ok: false,
        error: "Некоректний або повторний ID договору"
      });
    }

    ids.add(contract.id);
  }

  const fields = [
    "id",
    "tt_code",
    "contract_number",
    "contract_type",
    "object_name",
    "address",
    "landlord",
    "tenant",
    "signed_date",
    "start_date",
    "opening_date",
    "end_date",
    "contract_status",
    "renewal_terms",
    "area_sqm",
    "property_rights",
    "folder_url",
    "verification_status",
    "source_row",
    "tt_code_source",
    "contacts",
    "payment_terms",
    "critical_terms",
    "notes"
  ];

  const jsonFields = new Set([
    "contacts",
    "payment_terms",
    "critical_terms"
  ]);

  const columns = fields.join(", ");
  const placeholders = fields.map(
    (_, index) => `$${index + 1}`
  ).join(", ");

  const query = `
    INSERT INTO rent_contracts (${columns})
    VALUES (${placeholders})
    ON CONFLICT (id) DO NOTHING
  `;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    let imported = 0;
    let skipped = 0;

    for (const contract of contracts) {
      const values = fields.map(field => {
        const value = contract[field];

        if (jsonFields.has(field)) {
          return JSON.stringify(value ?? {});
        }

        return value === undefined || value === ""
          ? null
          : value;
      });

      const result = await client.query(query, values);

      if (result.rowCount === 1) {
        imported++;
      } else {
        skipped++;
      }
    }

    await client.query("COMMIT");

    return res.json({
      ok: true,
      received: contracts.length,
      imported,
      skipped,
      total: imported + skipped
    });
  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

const ExcelJS = require("exceljs");
const multer = require("multer");

const excelUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

app.post(
  "/api/contracts/import-excel",
  excelUpload.single("file"),
  async (req, res, next) => {
    const crypto = require("node:crypto");
    const token = process.env.RENT_IMPORT_TOKEN;
    const supplied = req.get("x-import-token") || "";

    if (!token) {
      return res.status(503).json({
        ok: false,
        error: "Ключ імпорту не налаштовано"
      });
    }

    const a = Buffer.from(token);
    const b = Buffer.from(supplied);

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      return res.status(403).json({
        ok: false,
        error: "Доступ заборонено"
      });
    }

    if (!pool) {
      return res.status(503).json({
        ok: false,
        error: "База даних не підключена"
      });
    }

    if (!req.file) {
      return res.status(400).json({
        ok: false,
        error: "Файл Excel не вибрано"
      });
    }

    try {
      const workbook = new ExcelJS.Workbook();
      await workbook.xlsx.load(req.file.buffer);

      const sheetNames = [
        "01_Реєстр договорів",
        "02_Сторони_контакти",
        "03_Умови оплат",
        "04_Критичні умови"
      ];

      const sheets = sheetNames.map(name =>
        workbook.getWorksheet(name)
      );

      if (sheets.some(sheet => !sheet)) {
        return res.status(400).json({
          ok: false,
          error: "У файлі відсутні необхідні вкладки"
        });
      }

      function value(row, column) {
        let v = row.getCell(column).value;

        if (v == null) return null;
        if (v instanceof Date) return v;

        if (typeof v === "object") {
          if (v.result !== undefined) v = v.result;
          else if (v.text !== undefined) v = v.text;
          else if (v.richText) {
            v = v.richText.map(x => x.text).join("");
          } else {
            v = row.getCell(column).text;
          }
        }

        if (v == null || String(v).trim() === "") {
          return null;
        }

        return v;
      }

      function dateValue(v) {
        if (v == null) return null;

        if (v instanceof Date) {
          if (isNaN(v.getTime())) return null;
          return v.toISOString().slice(0, 10);
        }

        if (typeof v === "number") {
          const date = new Date(
            Date.UTC(1899, 11, 30) +
            Math.round(v) * 86400000
          );
          return date.toISOString().slice(0, 10);
        }

        const s = String(v).trim();

        if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;

        const match = s.match(
          /^(\d{2})\.(\d{2})\.(\d{4})$/
        );

        if (match) {
          return `${match[3]}-${match[2]}-${match[1]}`;
        }

        return null;
      }

      function readDetails(sheet) {
        const result = new Map();
        const headers = [];

        sheet.getRow(1).eachCell((cell, col) => {
          headers[col] = String(cell.value || "");
        });

        sheet.eachRow((row, number) => {
          if (number === 1) return;

          const id = value(row, 1);
          if (!id) return;

          const data = {};

          for (let col = 2; col <= headers.length; col++) {
            if (!headers[col]) continue;

            const v = value(row, col);

            if (v !== null) {
              data[headers[col]] =
                v instanceof Date
                  ? dateValue(v)
                  : v;
            }
          }

          result.set(String(id).trim(), data);
        });

        return result;
      }

      const contacts = readDetails(sheets[1]);
      const payments = readDetails(sheets[2]);
      const critical = readDetails(sheets[3]);

      const contracts = [];
      const ids = new Set();
      const main = sheets[0];

      main.eachRow((row, number) => {
        if (number === 1) return;

        const id = String(value(row, 1) || "").trim();
        if (!id) return;

        if (!/^CTR-\d{4}$/.test(id) || ids.has(id)) {
          throw new Error(
            `Некоректний або повторний ID: ${id}`
          );
        }

        ids.add(id);

        const area = value(row, 18);
        const parsedArea = area == null
          ? null
          : Number(String(area).replace(",", "."));

        contracts.push({
          id,
          source_row: value(row, 2),
          tt_code: value(row, 3),
          tt_code_source: value(row, 4),
          contract_number: value(row, 6),
          contract_type: value(row, 7),
          object_name: value(row, 8),
          address: value(row, 9),
          landlord: value(row, 10),
          tenant: value(row, 11),
          signed_date: dateValue(value(row, 12)),
          start_date: dateValue(value(row, 13)),
          opening_date: dateValue(value(row, 14)),
          end_date: dateValue(value(row, 15)),
          contract_status: value(row, 16),
          renewal_terms: value(row, 17),
          area_sqm: Number.isFinite(parsedArea)
            ? parsedArea : null,
          property_rights: value(row, 19),
          folder_url: value(row, 20),
          verification_status: value(row, 21),
          contacts: contacts.get(id) || {},
          payment_terms: payments.get(id) || {},
          critical_terms: critical.get(id) || {},
          notes: null
        });
      });

      if (!contracts.length || contracts.length > 500) {
        return res.status(400).json({
          ok: false,
          error: "Некоректна кількість договорів"
        });
      }

      const fields = [
        "id", "tt_code", "contract_number",
        "contract_type", "object_name", "address",
        "landlord", "tenant", "signed_date",
        "start_date", "opening_date", "end_date",
        "contract_status", "renewal_terms",
        "area_sqm", "property_rights", "folder_url",
        "verification_status", "source_row",
        "tt_code_source", "contacts",
        "payment_terms", "critical_terms", "notes"
      ];

      const placeholders = fields.map(
        (_, i) => `$${i + 1}`
      ).join(", ");

      const query = `
        INSERT INTO rent_contracts (${fields.join(", ")})
        VALUES (${placeholders})
        ON CONFLICT (id) DO NOTHING
      `;

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        let imported = 0;
        let skipped = 0;

        for (const contract of contracts) {
          const values = fields.map(field => {
            const v = contract[field];

            if ([
              "contacts",
              "payment_terms",
              "critical_terms"
            ].includes(field)) {
              return JSON.stringify(v || {});
            }

            return v === undefined || v === "" ? null : v;
          });

          const result = await client.query(query, values);

          if (result.rowCount === 1) imported++;
          else skipped++;
        }

        await client.query("COMMIT");

        res.json({
          ok: true,
          received: contracts.length,
          imported,
          skipped
        });

      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }

    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/contracts/update-rent",
  excelUpload.single("file"),
  async (req, res, next) => {
    const crypto = require("node:crypto");
    const token = process.env.RENT_IMPORT_TOKEN;
    const supplied = req.get("x-import-token") || "";

    if (!token) {
      return res.status(503).json({
        ok: false,
        error: "Ключ імпорту не налаштовано"
      });
    }

    const a = Buffer.from(token);
    const b = Buffer.from(supplied);

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      return res.status(403).json({
        ok: false,
        error: "Доступ заборонено"
      });
    }

    if (!pool || !req.file) {
      return res.status(400).json({
        ok: false,
        error: "Немає підключення до БД або файла"
      });
    }

    try {
      const workbook = new ExcelJS.Workbook();
      await workbook.xlsx.load(req.file.buffer);

      const sheet = workbook.getWorksheet("Ф1 Ф2");

      if (!sheet) {
        return res.status(400).json({
          ok: false,
          error: "Не знайдено вкладку Ф1 Ф2"
        });
      }

      const headers = [
        "ID договору",
        "Ф1, грн",
        "Ф2, грн"
      ];

      if (
        sheet.getCell("A1").value !== headers[0] ||
        sheet.getCell("G1").value !== headers[1] ||
        sheet.getCell("H1").value !== headers[2]
      ) {
        return res.status(400).json({
          ok: false,
          error: "Структура Excel не відповідає шаблону"
        });
      }

      const rows = [];
      const ids = new Set();

      function readAmount(cell) {
        const value = cell.value;

        if (value === null || value === "") return null;

        if (
          typeof value !== "number" ||
          !Number.isFinite(value) ||
          value < 0 ||
          Math.round(value * 100) !== value * 100
        ) {
          throw new Error(
            `Некоректна сума в клітинці ${cell.address}`
          );
        }

        return value;
      }

      sheet.eachRow((row, number) => {
        if (number === 1) return;

        const id = String(row.getCell(1).value || "").trim();

        if (!id) return;

        if (!/^CTR-\d{4}$/.test(id) || ids.has(id)) {
          throw new Error(`Некоректний ID: ${id}`);
        }

        ids.add(id);

        rows.push({
          id,
          f1: readAmount(row.getCell(7)),
          f2: readAmount(row.getCell(8))
        });
      });

      if (rows.length !== 170) {
        return res.status(400).json({
          ok: false,
          error: `Очікується 170 договорів, отримано ${rows.length}`
        });
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        let updated = 0;
        let unchanged = 0;

        for (const row of rows) {
          const result = await client.query(
            `
              UPDATE rent_contracts
              SET
                rent_f1 = $2,
                rent_f2 = $3,
                updated_at = NOW()
              WHERE id = $1
                AND (
                  rent_f1 IS DISTINCT FROM $2::numeric OR
                  rent_f2 IS DISTINCT FROM $3::numeric
                )
              RETURNING id
            `,
            [row.id, row.f1, row.f2]
          );

          if (result.rowCount) updated++;
          else unchanged++;
        }

        const check = await client.query(
          `SELECT id FROM rent_contracts WHERE id = ANY($1::text[])`,
          [rows.map(row => row.id)]
        );

        if (check.rowCount !== rows.length) {
          throw new Error("Не всі ID знайдені в базі");
        }

        await client.query("COMMIT");

        res.json({
          ok: true,
          received: rows.length,
          updated,
          unchanged
        });

      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }

    } catch (error) {
      next(error);
    }
  }
);


const NEW_RENT_HEADERS = [
  'Код ТТ','№ договору','Вид договору','Об’єкт / населений пункт','Область','Адреса',
  'Орендодавець','Орендар','Дата підписання','Початок оренди','Дата відкриття ТТ',
  'Дата закінчення','Статус договору','Умови пролонгації','Площа, м²','Ф1, грн',
  'Ф2, грн','Права на приміщення','Папка документів (URL)','Статус перевірки',
  'Примітки','Контакт орендодавця','Телефон','Перенесення платежу',
  'Орендна плата (джерело)','Ф1 / б/н (умови)','Ф2 / нал. ТТ (умови)',
  'Ф2 / нал. каса (умови)','Строк/дата оплати','Комунальні послуги',
  'Ввідна потужність, кВт','Гарантійний платіж','Інші умови оплат',
  'Критичні умови / ДУ'
];

app.post('/api/contracts/import-new-excel', excelUpload.single('file'), async (req, res, next) => {
  const crypto = require('node:crypto');
  const secret = process.env.RENT_IMPORT_TOKEN || '';
  const provided = req.get('x-import-token') || '';
  const a = Buffer.from(secret);
  const b = Buffer.from(provided);

  if (!secret || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ ok: false, error: 'Невірний ключ імпорту' });
  }

  if (!pool) return res.status(503).json({ ok: false, error: 'База недоступна' });
  if (!req.file) return res.status(400).json({ ok: false, error: 'Не вибрано файл Excel' });

  try {
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(req.file.buffer);

    if (workbook.worksheets.length !== 1 || workbook.worksheets[0].name !== 'Нові договори') {
      return res.status(400).json({
        ok: false,
        error: 'Потрібен шаблон з одним аркушем «Нові договори»'
      });
    }

    const sheet = workbook.worksheets[0];

    const text = (row, col) => {
      const cell = row.getCell(col);
      const v = cell.value;

      if (v == null) return null;
      if (v instanceof Date) return v;

      if (typeof v === 'object') {
        if (v.result !== undefined) {
          return v.result == null ? null : String(v.result).trim();
        }
        if (v.text !== undefined) return String(v.text).trim() || null;
        return String(cell.text || '').trim() || null;
      }

      return String(v).trim() || null;
    };

    for (let col = 1; col <= NEW_RENT_HEADERS.length; col++) {
      if (text(sheet.getRow(1), col) !== NEW_RENT_HEADERS[col - 1]) {
        return res.status(400).json({
          ok: false,
          error: `Не збігається заголовок колонки ${col}. Скористайтеся шаблоном.`
        });
      }
    }

    function amount(v, line, col) {
      if (v === null) return null;

      const n = typeof v === 'number'
        ? v
        : Number(String(v).replace(/\s/g, '').replace(',', '.'));

      if (
        !Number.isFinite(n) ||
        n < 0 ||
        Math.abs(n * 100 - Math.round(n * 100)) > 1e-6
      ) {
        throw new Error(`Рядок ${line}: неправильне число в колонці ${col}`);
      }

      return n;
    }

    function date(v, line, col) {
      if (v === null) return null;

      let d;

      if (v instanceof Date) {
        d = v;
      } else if (typeof v === 'number') {
        d = new Date(Date.UTC(1899, 11, 30) + Math.round(v) * 86400000);
      } else if (/^\d{2}\.\d{2}\.\d{4}$/.test(String(v))) {
        const [dd, mm, yyyy] = String(v).split('.');
        d = new Date(`${yyyy}-${mm}-${dd}T00:00:00Z`);

        if (
          d.getUTCDate() !== Number(dd) ||
          d.getUTCMonth() + 1 !== Number(mm) ||
          d.getUTCFullYear() !== Number(yyyy)
        ) d = null;
      } else if (/^\d{4}-\d{2}-\d{2}$/.test(String(v))) {
        d = new Date(`${v}T00:00:00Z`);

        if (
          isNaN(d.getTime()) ||
          d.toISOString().slice(0, 10) !== v
        ) d = null;
      }

      if (!d || isNaN(d.getTime())) {
        throw new Error(`Рядок ${line}: неправильна дата в колонці ${col}`);
      }

      return d.toISOString().slice(0, 10);
    }

    const rows = [];

    sheet.eachRow((r, i) => {
      if (i === 1) return;

      const vals = NEW_RENT_HEADERS.map((_, col) => text(r, col + 1));

      if (vals.every(v => v === null)) return;

      if (!vals[1] || !vals[3] || !vals[4] || !vals[5] || !vals[6]) {
        throw new Error(
          `Рядок ${i}: обов'язкові №, Об’єкт, Область, Адреса, Орендодавець`
        );
      }

      const payment = {};

      [
        ['Орендна плата (джерело)', 24],
        ['Ф1 / б/н', 25],
        ['Ф2 / нал. ТТ', 26],
        ['Ф2 / нал. каса', 27],
        ['Строк/дата оплати', 28],
        ['Комунальні послуги', 29],
        ['Ввідна потужність, кВт', 30],
        ['Гарантійний платіж', 31],
        ['Інші умови оплат', 32]
      ].forEach(([key, idx]) => {
        if (vals[idx] !== null) payment[key] = vals[idx];
      });

      const contacts = {};

      if (vals[21]) {
        contacts['Контакт орендодавця (реєстр)'] = vals[21];
      }

      if (vals[22]) {
        contacts['Телефон'] = vals[22];
      }

      const critical = {};

      if (vals[23]) critical['Примітка'] = vals[23];
      if (vals[33]) critical['Інше'] = vals[33];

      rows.push({
        line: i,
        tt_code: vals[0],
        contract_number: vals[1],
        contract_type: vals[2],
        object_name: vals[3],
        region: vals[4],
        address: vals[5],
        landlord: vals[6],
        tenant: vals[7],
        signed_date: date(vals[8], i, 9),
        start_date: date(vals[9], i, 10),
        opening_date: date(vals[10], i, 11),
        end_date: date(vals[11], i, 12),
        contract_status: vals[12],
        renewal_terms: vals[13],
        area_sqm: amount(vals[14], i, 15),
        rent_f1: amount(vals[15], i, 16),
        rent_f2: amount(vals[16], i, 17),
        property_rights: vals[17],
        folder_url: vals[18],
        verification_status: vals[19],
        notes: vals[20],
        payment_terms: JSON.stringify(payment),
        contacts: JSON.stringify(contacts),
        critical_terms: JSON.stringify(critical)
      });
    });

    if (!rows.length || rows.length > 500) {
      return res.status(400).json({
        ok: false,
        error: 'У файлі має бути від 1 до 500 нових договорів'
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      await client.query('SELECT pg_advisory_xact_lock(731091, 2026)');

      const existing = await client.query(
        'SELECT contract_number, landlord, address FROM rent_contracts'
      );

      const norm = v => String(v || '')
        .trim()
        .toLocaleLowerCase('uk')
        .replace(/\s+/g, ' ');

      const fingerprint = o => [
        o.contract_number,
        o.landlord,
        o.address
      ].map(norm).join('|');

      const seen = new Set(existing.rows.map(fingerprint));

      for (const row of rows) {
        const key = fingerprint(row);

        if (seen.has(key)) {
          await client.query('ROLLBACK');

          return res.status(409).json({
            ok: false,
            error: `Дубль договору в рядку ${row.line}: № ${row.contract_number}. Нічого не імпортовано.`
          });
        }

        seen.add(key);
      }

      const last = await client.query(
        "SELECT COALESCE(MAX(SUBSTRING(id FROM '^CTR-([0-9]+)$')::integer), 0) AS n FROM rent_contracts"
      );

      let n = Number(last.rows[0].n);
      const ids = [];

      const fields = [
        'id',
        'tt_code',
        'contract_number',
        'contract_type',
        'object_name',
        'region',
        'address',
        'landlord',
        'tenant',
        'signed_date',
        'start_date',
        'opening_date',
        'end_date',
        'contract_status',
        'renewal_terms',
        'area_sqm',
        'rent_f1',
        'rent_f2',
        'property_rights',
        'folder_url',
        'verification_status',
        'notes',
        'payment_terms',
        'contacts',
        'critical_terms'
      ];

      const sql = `
        INSERT INTO rent_contracts (${fields.join(',')})
        VALUES (${fields.map((_, i) => `$${i + 1}`).join(',')})
      `;

      for (const row of rows) {
        const id = `CTR-${String(++n).padStart(4, '0')}`;

        await client.query(
          sql,
          fields.map(f => f === 'id' ? id : row[f])
        );

        ids.push(id);
      }

      await client.query('COMMIT');

      return res.json({
        ok: true,
        imported: ids.length,
        ids
      });

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

  } catch (error) {
    if (/^Рядок |^Невірн|^Не збіга/.test(error.message)) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    next(error);
  }
});


function checkRentActionToken(req, res) {
  const crypto = require("node:crypto");
  const expected = process.env.RENT_IMPORT_TOKEN || "";
  const provided = req.get("x-import-token") || "";

  const a = Buffer.from(expected);
  const b = Buffer.from(provided);

  if (
    !expected ||
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    res.status(403).json({
      ok: false,
      error: "Невірний ключ редагування"
    });
    return false;
  }

  return true;
}

app.post("/api/contracts/:id/archive", async (req, res, next) => {
  if (!checkRentActionToken(req, res)) return;

  if (!pool) {
    return res.status(503).json({
      ok: false,
      error: "База недоступна"
    });
  }

  if (!/^CTR-\d{4}$/.test(req.params.id)) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний ID договору"
    });
  }

  try {
    const result = await pool.query(
      `UPDATE rent_contracts
       SET archived_at = NOW(), updated_at = NOW()
       WHERE id = $1 AND archived_at IS NULL
       RETURNING id`,
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        ok: false,
        error: "Договір не знайдено в основному реєстрі"
      });
    }

    res.json({ ok: true, id: req.params.id });
  } catch (error) {
    next(error);
  }
});

app.post("/api/contracts/:id/restore", async (req, res, next) => {
  if (!checkRentActionToken(req, res)) return;

  if (!pool) {
    return res.status(503).json({
      ok: false,
      error: "База недоступна"
    });
  }

  if (!/^CTR-\d{4}$/.test(req.params.id)) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний ID договору"
    });
  }

  try {
    const result = await pool.query(
      `UPDATE rent_contracts
       SET archived_at = NULL, updated_at = NOW()
       WHERE id = $1 AND archived_at IS NOT NULL
       RETURNING id`,
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        ok: false,
        error: "Договір не знайдено в архіві"
      });
    }

    res.json({ ok: true, id: req.params.id });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/contracts/:id/permanent", async (req, res, next) => {
  if (!checkRentActionToken(req, res)) return;

  if (!pool) {
    return res.status(503).json({
      ok: false,
      error: "База недоступна"
    });
  }

  if (!/^CTR-\d{4}$/.test(req.params.id)) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний ID договору"
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const found = await client.query(
      "SELECT id FROM rent_contracts WHERE id = $1 FOR UPDATE",
      [req.params.id]
    );

    if (!found.rowCount) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        ok: false,
        error: "Договір не знайдено"
      });
    }

    await client.query(
      "DELETE FROM rent_contract_history WHERE contract_id = $1",
      [req.params.id]
    );

    await client.query(
      "DELETE FROM rent_contracts WHERE id = $1",
      [req.params.id]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      id: req.params.id
    });
  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

app.get("/api/contracts/:id/history", async (req, res, next) => {
  try {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        error: "База даних не підключена"
      });
    }

    const id = req.params.id;

    if (!/^CTR-\d{4}$/.test(id)) {
      return res.status(400).json({
        ok: false,
        error: "Некоректний ID договору"
      });
    }

    const result = await pool.query(
      `
        SELECT
          id,
          contract_id,
          field_name,
          old_value,
          new_value,
          changed_at
        FROM rent_contract_history
        WHERE contract_id = $1
        ORDER BY changed_at DESC, id DESC
      `,
      [id]
    );

    res.json({
      ok: true,
      contract_id: id,
      total: result.rowCount,
      history: result.rows
    });

  } catch (error) {
    next(error);
  }
});

app.patch("/api/contracts/:id", async (req, res, next) => {
  const crypto = require("node:crypto");
  const token = process.env.RENT_IMPORT_TOKEN;
  const supplied = req.get("x-import-token") || "";

  if (!token) {
    return res.status(503).json({
      ok: false,
      error: "Ключ редагування не налаштований"
    });
  }

  const expected = Buffer.from(token);
  const received = Buffer.from(supplied);

  if (
    expected.length !== received.length ||
    !crypto.timingSafeEqual(expected, received)
  ) {
    return res.status(403).json({
      ok: false,
      error: "Доступ до редагування заборонено"
    });
  }

  if (!pool) {
    return res.status(503).json({
      ok: false,
      error: "База даних не підключена"
    });
  }

  const id = req.params.id;

  if (!/^CTR-\d{4}$/.test(id)) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний ID договору"
    });
  }

  const allowedFields = [
    "tt_code", "contract_number", "contract_type",
    "object_name", "address", "landlord", "tenant",
    "signed_date", "start_date", "opening_date",
    "end_date", "contract_status", "renewal_terms",
    "area_sqm", "property_rights", "folder_url",
    "verification_status", "contacts",
    "payment_terms", "critical_terms", "notes",
    "rent_f1", "rent_f2", "region"
  ];

  const jsonFields = new Set([
    "contacts", "payment_terms", "critical_terms"
  ]);

  const updates = [];
  const values = [];

  for (const field of allowedFields) {
    if (!Object.prototype.hasOwnProperty.call(req.body, field)) {
      continue;
    }

    let value = req.body[field];

    if (jsonFields.has(field)) {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return res.status(400).json({
          ok: false,
          error: `Некоректне значення поля ${field}`
        });
      }

      value = JSON.stringify(value);
    } else if (value === "") {
      value = null;
    }

    values.push(value);
    updates.push(`${field} = $${values.length}`);
  }

  if (!updates.length) {
    return res.status(400).json({
      ok: false,
      error: "Немає даних для оновлення"
    });
  }

  values.push(id);

  try {
    const result = await pool.query(
      `UPDATE rent_contracts
       SET ${updates.join(", ")}, updated_at = NOW()
       WHERE id = $${values.length}
       RETURNING *`,
      values
    );

    if (!result.rowCount) {
      return res.status(404).json({
        ok: false,
        error: "Договір не знайдено"
      });
    }

    res.json({
      ok: true,
      contract: result.rows[0]
    });
  } catch (error) {
    next(error);
  }
});

app.use((error, req, res, next) => {
  console.error(error);

  res.status(error.message === "Доступ із цього сайту заборонено" ? 403 : 500).json({
    ok: false,
    error:
      error.message === "Доступ із цього сайту заборонено"
        ? error.message
        : "Внутрішня помилка сервера"
  });
});

async function autofillContractRegions() {
  const fs = require("node:fs");
  const path = require("node:path");
  const csvPath = path.join(__dirname, "settlements.csv");

  if (!fs.existsSync(csvPath)) {
    console.warn("REGIONS: settlements.csv не знайдено, автозаповнення пропущено");
    return;
  }

  const normalize = value => String(value ?? "")
    .toLocaleLowerCase("uk")
    .replace(/[ʼ’`]/g, "'")
    .replace(/\s+/g, " ")
    .trim();

  const cleanCity = value => normalize(value)
    .replace(/^(?:(?:місто|село|селище|смт)\s+|(?:м|с|смт)\.\s*)/u, "");

  const rows = fs.readFileSync(csvPath, "utf8")
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/)
    .filter(Boolean);

  const headers = rows.shift().split(";");
  const column = name => headers.indexOf(name);

  const settlements = new Map();
  const allRegions = new Set();

  for (const line of rows) {
    const cells = line.split(";");
    const name = cells[column("name")]?.trim();
    const type = normalize(cells[column("type")]);
    let region = cells[column("oblast")]?.trim() || "";
    const raion = cells[column("raion")]?.trim() || "";
    const hromada = cells[column("hromada")]?.trim() || "";

    if (!name) continue;

    if (!region && name === "Київ" && type === "місто") {
      region = "м. Київ";
    }
    if (!region && name === "Севастополь" && type === "місто") {
      region = "м. Севастополь";
    }

    if (!region) continue;

    allRegions.add(region);

    const key = normalize(name);
    if (!settlements.has(key)) settlements.set(key, []);

    settlements.get(key).push({ name, type, region, raion, hromada });
  }

  function findRegion(objectName, address) {
    const original = normalize(objectName);
    const city = cleanCity(objectName);
    const addressText = normalize(address);

    if (!city) return null;

    let matches = [...(settlements.get(city) || [])];

    if (!matches.length) return null;

    // Якщо область прямо зазначена в адресі, вона має пріоритет.
    const explicitRegion = [...allRegions].find(region => {
      const lower = normalize(region);

      if (lower.startsWith("м. ")) {
        return false;
      }

      if (lower === "автономна республіка крим") {
        return addressText.includes(lower);
      }

      const stem = lower.slice(0, 5);
      const escaped = stem.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

      return new RegExp(
        `(?:^|[^а-яіїєґ])${escaped}[а-яіїєґ'-]*\\s+обл(?:асть|асті|\\.)?`,
        "iu"
      ).test(addressText);
    });

    if (explicitRegion) {
      const filtered = matches.filter(item => item.region === explicitRegion);
      if (filtered.length) matches = filtered;
      else return null;
    }

    // Район і громада уточнюють однойменні населені пункти.
    if (matches.length > 1) {
      const byRaion = matches.filter(item =>
        item.raion &&
        addressText.includes(normalize(item.raion))
      );
      if (byRaion.length) matches = byRaion;
    }

    if (matches.length > 1) {
      const byHromada = matches.filter(item =>
        item.hromada &&
        addressText.includes(normalize(item.hromada))
      );
      if (byHromada.length) matches = byHromada;
    }

    // Тип враховуємо, якщо він дійсно зазначений.
    if (matches.length > 1) {
      let requiredType = "";

      if (/^(?:м\.|місто\s)/u.test(original)) requiredType = "місто";
      if (/^(?:с\.|село\s)/u.test(original)) requiredType = "село";

      if (requiredType) {
        const byType = matches.filter(item => item.type === requiredType);
        if (byType.length) matches = byType;
      }
    }

    const regions = [...new Set(matches.map(item => item.region))];

    return regions.length === 1 ? regions[0] : null;
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(`
      CREATE TABLE IF NOT EXISTS rent_system_migrations (
        migration_key TEXT PRIMARY KEY,
        completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const marker = "initial_region_autofill_v1";

    const alreadyDone = await client.query(
      "SELECT 1 FROM rent_system_migrations WHERE migration_key = $1",
      [marker]
    );

    if (alreadyDone.rowCount) {
      await client.query("COMMIT");
      return;
    }

    const contracts = await client.query(`
      SELECT id, object_name, address
      FROM rent_contracts
      WHERE region IS NULL OR BTRIM(region) = ''
    `);

    let updated = 0;

    for (const contract of contracts.rows) {
      const region = findRegion(contract.object_name, contract.address);
      if (!region) continue;

      const result = await client.query(
        `UPDATE rent_contracts
         SET region = $2, updated_at = NOW()
         WHERE id = $1 AND (region IS NULL OR BTRIM(region) = '')`,
        [contract.id, region]
      );

      updated += result.rowCount;
    }

    await client.query(
      "INSERT INTO rent_system_migrations (migration_key) VALUES ($1)",
      [marker]
    );

    await client.query("COMMIT");

    console.log(
      `REGIONS: автозаповнено ${updated} із ${contracts.rowCount} договорів`
    );
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("REGIONS AUTOFILL ERROR:", error.message);
  } finally {
    client.release();
  }
}


async function initializeRentAuth() {
  const crypto = require("node:crypto");
  const { promisify } = require("node:util");
  const scrypt = promisify(crypto.scrypt);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS rent_users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('admin', 'editor', 'viewer')),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
      session_version INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS rent_user_sessions (
      id UUID PRIMARY KEY,
      user_id BIGINT NOT NULL
        REFERENCES rent_users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      session_version INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_rent_sessions_user
    ON rent_user_sessions(user_id)
  `);

  const existing = await pool.query(
    "SELECT COUNT(*)::integer AS total FROM rent_users"
  );

  if (existing.rows[0].total > 0) {
    console.log("AUTH: таблиці користувачів готові");
    return;
  }

  const email = String(process.env.RENT_ADMIN_EMAIL || "")
    .trim()
    .toLowerCase();

  const password = String(
    process.env.RENT_ADMIN_TEMP_PASSWORD || ""
  );

  if (!email || password.length < 4) {
    console.warn(
      "AUTH: для першого адміністратора потрібно " +
      "RENT_ADMIN_EMAIL і RENT_ADMIN_TEMP_PASSWORD " +
      "(мінімум 4 символи)"
    );
    return;
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hash = (await scrypt(password, salt, 64)).toString("hex");
  const passwordHash = `scrypt:${salt}:${hash}`;

  await pool.query(
    `INSERT INTO rent_users (
      name, email, password_hash, role,
      is_active, must_change_password
    )
    VALUES ($1, $2, $3, 'admin', TRUE, TRUE)
    ON CONFLICT (email) DO NOTHING`,
    ["Адміністратор", email, passwordHash]
  );

  console.log("AUTH: перший адміністратор створений");
}

async function initializeDatabase() {
  if (!pool) {
    console.error("DATABASE_URL відсутня");
    return;
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS rent_contracts (
        id VARCHAR(30) PRIMARY KEY,
        tt_code TEXT,
        contract_number TEXT,
        contract_type TEXT,
        object_name TEXT,
        address TEXT,
        landlord TEXT,
        tenant TEXT,
        signed_date DATE,
        start_date DATE,
        opening_date DATE,
        end_date DATE,
        contract_status TEXT,
        renewal_terms TEXT,
        area_sqm NUMERIC(12,2),
        property_rights TEXT,
        folder_url TEXT,
        verification_status TEXT,

        source_row INTEGER,
        tt_code_source TEXT,

        contacts JSONB NOT NULL DEFAULT '{}'::jsonb,
        payment_terms JSONB NOT NULL DEFAULT '{}'::jsonb,
        critical_terms JSONB NOT NULL DEFAULT '{}'::jsonb,

        notes TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await pool.query(`
      ALTER TABLE rent_contracts
        ADD COLUMN IF NOT EXISTS rent_f1 NUMERIC(14,2),
        ADD COLUMN IF NOT EXISTS rent_f2 NUMERIC(14,2),
        ADD COLUMN IF NOT EXISTS region TEXT,
        ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
    `);

    console.log("DATABASE RENT FIELDS: ready");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS rent_contract_history (
        id BIGSERIAL PRIMARY KEY,
        contract_id VARCHAR(30) NOT NULL
          REFERENCES rent_contracts(id),
        field_name TEXT NOT NULL,
        old_value JSONB,
        new_value JSONB,
        changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_rent_history_contract
        ON rent_contract_history(contract_id, changed_at DESC);

      CREATE OR REPLACE FUNCTION log_rent_contract_changes()
      RETURNS TRIGGER AS $$
      DECLARE
        field_record RECORD;
        old_data JSONB;
        new_data JSONB;
      BEGIN
        old_data := to_jsonb(OLD) - 'updated_at' - 'created_at';
        new_data := to_jsonb(NEW) - 'updated_at' - 'created_at';

        FOR field_record IN
          SELECT
            n.key,
            o.value AS previous_value,
            n.value AS current_value
          FROM jsonb_each(new_data) n
          JOIN jsonb_each(old_data) o ON o.key = n.key
          WHERE o.value IS DISTINCT FROM n.value
        LOOP
          INSERT INTO rent_contract_history (
            contract_id,
            field_name,
            old_value,
            new_value
          )
          VALUES (
            NEW.id,
            field_record.key,
            field_record.previous_value,
            field_record.current_value
          );
        END LOOP;

        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;

      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_trigger
          WHERE tgname = 'rent_contract_audit_trigger'
            AND tgrelid = 'rent_contracts'::regclass
        ) THEN
          CREATE TRIGGER rent_contract_audit_trigger
          AFTER UPDATE ON rent_contracts
          FOR EACH ROW
          EXECUTE FUNCTION log_rent_contract_changes();
        END IF;
      END;
      $$;
    `);

    console.log("DATABASE HISTORY: ready");

    await autofillContractRegions();    

    console.log("DATABASE TABLES: rent_contracts ready");

    await initializeRentAuth();    
  } catch (error) {
    console.error("DATABASE INIT ERROR:", error.message);
  }
}

initializeDatabase();

const server = app.listen(PORT, () => {
  console.log(`Rent Admin API запущено на порті ${PORT}`);
});

async function shutdown() {
  console.log("Зупинка Rent Admin API...");

  server.close(async () => {
    if (pool) {
      await pool.end();
    }

    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
