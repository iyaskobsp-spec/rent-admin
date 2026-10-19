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

// Єдина перевірка авторизації та ролей для всіх маршрутів договорів
app.use("/api/contracts", rentRequireSession, (req, res, next) => {
  if (req.rentUser.must_change_password) {
    return res.status(403).json({
      ok: false,
      error: "Спочатку змініть тимчасовий пароль"
    });
  }

  const path = req.path;
  const method = req.method;

  const isReadOnly =
    method === "GET";

  const isPermanentDelete =
    method === "DELETE" &&
    /^\/CTR-\d+\/permanent$/.test(path);

  if (isReadOnly) {
    return next();
  }

  if (isPermanentDelete && req.rentUser.role !== "admin") {
    return res.status(403).json({
      ok: false,
      error: "Видаляти договори може лише адміністратор"
    });
  }

  if (!["admin", "editor"].includes(req.rentUser.role)) {
    return res.status(403).json({
      ok: false,
      error: "Недостатньо прав для зміни договорів"
    });
  }

  next();
});


app.get("/api/contracts/export-excel", async (req, res, next) => {
  try {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        error: "База даних недоступна"
      });
    }

    const idsParam = String(req.query.ids || "");
    const ids = idsParam
      ? idsParam.split(",").map(id => id.trim())
      : [];

    if (
      ids.length > 500 ||
      ids.some(id => !/^CTR-\d{4,}$/.test(id)) ||
      new Set(ids).size !== ids.length
    ) {
      return res.status(400).json({
        ok: false,
        error: "Некоректний перелік договорів для експорту"
      });
    }

    const archive = req.query.scope === "archive";

    const result = ids.length
      ? await pool.query(
          `SELECT *
           FROM rent_contracts
           WHERE id = ANY($1::text[])
             AND archived_at IS ${archive ? "NOT NULL" : "NULL"}
           ORDER BY array_position($1::text[], id)`,
          [ids]
        )
      : { rows: [] };

    const workbook = new ExcelJS.Workbook();
    workbook.creator = "Управління орендою";
    workbook.created = new Date();

    const sheet = workbook.addWorksheet(
      archive ? "Архів договорів" : "Реєстр договорів",
      {
        views: [{ state: "frozen", ySplit: 1 }]
      }
    );

    const columns = [
      ["id", "ID договору", 17],
      ["tt_code", "Код ТТ", 14],
      ["contract_number", "№ договору", 22],
      ["contract_type", "Вид договору", 22],
      ["object_name", "Об'єкт / населений пункт", 30],
      ["region", "Область", 23],
      ["address", "Адреса", 45],
      ["landlord", "Орендодавець", 35],
      ["tenant", "Орендар", 35],
      ["signed_date", "Дата підписання", 20],
      ["start_date", "Початок оренди", 20],
      ["opening_date", "Дата відкриття ТТ", 22],
      ["end_date", "Дата закінчення", 20],
      ["contract_status", "Статус договору", 25],
      ["renewal_terms", "Умови пролонгації", 45],
      ["area_sqm", "Площа, м²", 16],
      ["rent_f1", "Ф1, грн", 18],
      ["rent_f2", "Ф2, грн", 18],
      ["rent_total", "Разом Ф1 + Ф2, грн", 22],
      ["property_rights", "Права на приміщення", 35],
      ["folder_url", "Папка документів", 48],
      ["verification_status", "Статус перевірки", 24],
      ["payment_terms", "Умови оплат / гарантійні платежі", 55],
      ["contacts", "Контакти та реквізити", 45],
      ["critical_terms", "Критичні умови / ДУ", 50],
      ["notes", "Примітки", 45]
    ];

    sheet.columns = columns.map(([key, header, width]) => ({
      header,
      key,
      width
    }));

    function exportDate(value) {
      if (!value) return null;

      const date = value instanceof Date
        ? value.toISOString().slice(0, 10)
        : String(value).slice(0, 10);

      const match = date.match(/^(\d{4})-(\d{2})-(\d{2})$/);

      return match
        ? `${match[3]}.${match[2]}.${match[1]}`
        : date;
    }

    function exportObject(value) {
      if (!value) return "";

      if (typeof value === "string") {
        try {
          value = JSON.parse(value);
        } catch {
          return value;
        }
      }

      if (typeof value !== "object" || Array.isArray(value)) {
        return String(value);
      }

      return Object.entries(value)
        .filter(([, item]) =>
          item !== null &&
          item !== undefined &&
          String(item).trim() !== ""
        )
        .map(([key, item]) => `${key}: ${item}`)
        .join("\n");
    }

    const dateKeys = new Set([
      "signed_date", "start_date", "opening_date", "end_date"
    ]);

    const objectKeys = new Set([
      "payment_terms", "contacts", "critical_terms"
    ]);

    for (const contract of result.rows) {
      const f1 = contract.rent_f1 == null
        ? null : Number(contract.rent_f1);

      const f2 = contract.rent_f2 == null
        ? null : Number(contract.rent_f2);

      const total = f1 === null && f2 === null
        ? null : (f1 || 0) + (f2 || 0);

      const record = {};

      for (const [key] of columns) {
        let value;

        if (key === "rent_total") {
          value = total;
        } else if (dateKeys.has(key)) {
          value = exportDate(contract[key]);
        } else if (objectKeys.has(key)) {
          value = exportObject(contract[key]);
        } else if (["area_sqm", "rent_f1", "rent_f2"].includes(key)) {
          value = contract[key] == null
            ? null : Number(contract[key]);
        } else {
          value = contract[key];
        }

        record[key] = value ?? "";
      }

      sheet.addRow(record);
    }

    const header = sheet.getRow(1);
    header.height = 32;

    header.eachCell(cell => {
      cell.font = {
        bold: true,
        color: { argb: "FFFFFFFF" }
      };
      cell.fill = {
        type: "pattern",
        pattern: "solid",
        fgColor: { argb: "FF233B5A" }
      };
      cell.alignment = {
        vertical: "middle",
        wrapText: true
      };
    });

    for (let rowNumber = 2; rowNumber <= sheet.rowCount; rowNumber++) {
      const row = sheet.getRow(rowNumber);

      row.eachCell({ includeEmpty: true }, cell => {
        cell.alignment = {
          vertical: "top",
          wrapText: true
        };
        cell.border = {
          bottom: {
            style: "hair",
            color: { argb: "FFE1E8F1" }
          }
        };

        if (rowNumber % 2 === 0) {
          cell.fill = {
            type: "pattern",
            pattern: "solid",
            fgColor: { argb: "FFF5F8FC" }
          };
        }
      });
    }

    for (const key of ["area_sqm", "rent_f1", "rent_f2", "rent_total"]) {
      sheet.getColumn(key).numFmt = '#,##0.00';
    }

    sheet.autoFilter = {
      from: { row: 1, column: 1 },
      to: { row: Math.max(sheet.rowCount, 2), column: columns.length }
    };

    const buffer = await workbook.xlsx.writeBuffer();

    const date = new Date().toISOString().slice(0, 10);
    const filename = archive
      ? `rent_archive_${date}.xlsx`
      : `rent_registry_${date}.xlsx`;

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`
    );
    res.setHeader("Cache-Control", "no-store");

    return res.send(Buffer.from(buffer));
  } catch (error) {
    next(error);
  }
});

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

app.post("/api/contracts/:id/archive", async (req, res, next) => {

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

// ========================================
// ПЛАТІЖНИЙ КАЛЕНДАР: БАЗА ДАНИХ
// ========================================

async function initializeRentCalendar() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS rent_calendar_quota (
      week_start DATE PRIMARY KEY,
      amount NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK(amount >= 0),
      updated_by BIGINT REFERENCES rent_users(id) ON DELETE SET NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS rent_calendar_items (
      id BIGSERIAL PRIMARY KEY,
      budget_line_id BIGINT NOT NULL REFERENCES rent_budget_lines(id),
      contract_id TEXT NOT NULL,
      form TEXT NOT NULL CHECK(form IN ('f1','f2')),
      original_month VARCHAR(7) NOT NULL,
      original_week INTEGER NOT NULL,
      original_amount NUMERIC(14,2) NOT NULL CHECK(original_amount >= 0),
      amount NUMERIC(14,2) NOT NULL CHECK(amount >= 0),
      due_date DATE NOT NULL,
      initial_date DATE NOT NULL,
      parent_id BIGINT REFERENCES rent_calendar_items(id),
      funded NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK(funded >= 0),
      manually_funded BOOLEAN NOT NULL DEFAULT FALSE,
      actual NUMERIC(14,2),
      confirmed_at TIMESTAMPTZ,
      confirmed_by BIGINT REFERENCES rent_users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (funded <= amount),
      CHECK (actual IS NULL OR actual >= 0)
    );

    CREATE UNIQUE INDEX IF NOT EXISTS rent_calendar_origin_unique
      ON rent_calendar_items(budget_line_id, form, original_week)
      WHERE parent_id IS NULL;

    CREATE INDEX IF NOT EXISTS rent_calendar_due_idx
      ON rent_calendar_items(due_date);

    CREATE TABLE IF NOT EXISTS rent_calendar_events (
      id BIGSERIAL PRIMARY KEY,
      item_id BIGINT REFERENCES rent_calendar_items(id),
      action TEXT NOT NULL,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      actor_id BIGINT REFERENCES rent_users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

function calendarIso(date) {
  return (
    date instanceof Date
      ? date.toISOString()
      : String(date)
  ).slice(0, 10);
}

function calendarMonday(iso) {
  const d = new Date(`${iso}T00:00:00Z`);
  const day = (d.getUTCDay() + 6) % 7;

  d.setUTCDate(d.getUTCDate() - day);

  return calendarIso(d);
}

function calendarMoneyInt(raw) {
  if (
    raw === null ||
    raw === undefined ||
    raw === "" ||
    !/^\d+(?:\.\d{1,2})?$/.test(String(raw))
  ) {
    return null;
  }

  const n = Math.round(Number(raw) * 100);

  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

function calendarValidDate(raw) {
  if (
    typeof raw !== "string" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(raw)
  ) {
    return false;
  }

  const d = new Date(`${raw}T00:00:00Z`);

  return !Number.isNaN(d.getTime()) &&
    calendarIso(d) === raw;
}

function calendarMovable(terms) {
  const data = terms || {};

  const text = Object.entries(data)
    .filter(([key, value]) =>
      /перенес|примітк|shift/i.test(key) ||
      /перенес/i.test(String(value || ""))
    )
    .map(([key, value]) => `${key}: ${value}`)
    .join(" ")
    .toLowerCase();

  if (
    !text ||
    /не можна|не дозвол|неможлив|заборон|відсутн|без перенес|перенес[^.;]{0,40}:\s*(ні|ніт|no|false)/i
      .test(text)
  ) {
    return false;
  }

  return /можлив|дозвол|можна|так|погоджен/i.test(text);
}

function calendarWeekFinished(monday) {
  const next = new Date(`${monday}T00:00:00Z`);
  next.setUTCDate(next.getUTCDate() + 7);

  const now = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Europe/Kyiv",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(new Date());

  return now >= calendarIso(next);
}

function calendarRole(req, res, next) {
  if (req.rentUser.must_change_password) {
    return res.status(403).json({
      ok: false,
      error: "Змініть тимчасовий пароль"
    });
  }

  if (
    req.method !== "GET" &&
    !["admin", "editor"].includes(req.rentUser.role)
  ) {
    return res.status(403).json({
      ok: false,
      error: "Недостатньо прав"
    });
  }

  next();
}

app.use(
  "/api/calendar",
  rentRequireSession,
  calendarRole
);

// ========================================
// ЗАВАНТАЖЕННЯ ПЛАНУ З БЮДЖЕТУ
// ========================================

app.post(
  "/api/calendar/:month/initialize",
  async (req, res, next) => {
    const month = req.params.month;

    if (!rentBudgetValidMonth(month)) {
      return res.status(400).json({
        ok: false,
        error: "Некоректний місяць"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const budget = await client.query(
        `SELECT id
         FROM rent_budgets
         WHERE budget_month = $1
           AND status = 'approved'`,
        [month]
      );

      if (!budget.rowCount) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error: "Спочатку затвердіть бюджет цього місяця"
        });
      }

      const lines = await client.query(
        `SELECT *
         FROM rent_budget_lines
         WHERE budget_id = $1`,
        [budget.rows[0].id]
      );

      const weeks = rentBudgetWeeks(month);
      let added = 0;

      for (const line of lines.rows) {
        for (const form of ["f1", "f2"]) {
          const amounts = line[`weeks_${form}`] || [];

          for (let i = 0; i < weeks.length; i++) {
            const cents = calendarMoneyInt(
              amounts[i] ?? 0
            );

            if (!cents) continue;

            const from = weeks[i].from;
            const to = weeks[i].to;

            // Початкова дата в межах бюджетного тижня.
            // Далі користувач може перенести допустимий платіж.
            let chosen = from;

            for (let day = from; day <= to; day++) {
              const date = new Date(
                `${month}-${String(day).padStart(2, "0")}T00:00:00Z`
              );

              if (date.getUTCDay() === 1) {
                chosen = day;
                break;
              }

              if (date.getUTCDay() === 5) {
                chosen = day;
                break;
              }
            }

            const due =
              `${month}-${String(chosen).padStart(2, "0")}`;

            const inserted = await client.query(
              `INSERT INTO rent_calendar_items (
                 budget_line_id,
                 contract_id,
                 form,
                 original_month,
                 original_week,
                 original_amount,
                 amount,
                 due_date,
                 initial_date
               )
               VALUES ($1,$2,$3,$4,$5,$6,$6,$7,$7)
               ON CONFLICT (
                 budget_line_id,
                 form,
                 original_week
               )
               WHERE parent_id IS NULL
               DO NOTHING
               RETURNING id`,
              [
                line.id,
                line.contract_id,
                form,
                month,
                i,
                cents / 100,
                due
              ]
            );

            added += inserted.rowCount;
          }
        }
      }

      await client.query("COMMIT");

      res.json({ ok: true, added });
    } catch (error) {
      await client.query("ROLLBACK");
      next(error);
    } finally {
      client.release();
    }
  }
);

// ========================================
// ОТРИМАННЯ ПЛАТЕЖІВ КАЛЕНДАРЯ
// ========================================

app.get("/api/calendar/:month", async (req, res, next) => {
  const month = req.params.month;

  if (!rentBudgetValidMonth(month)) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний місяць"
    });
  }

  try {
    const budgetResult = await pool.query(
      `SELECT id, status
       FROM rent_budgets
       WHERE budget_month = $1`,
      [month]
    );

    const budget = budgetResult.rows[0] || null;

    let lines = [];

    if (budget) {
      const lineResult = await pool.query(
        `SELECT
           l.*,
           c.payment_terms,
           c.critical_terms
         FROM rent_budget_lines l
         LEFT JOIN rent_contracts c
           ON c.id = l.contract_id
         WHERE l.budget_id = $1
         ORDER BY l.tt_code NULLS LAST, l.contract_id`,
        [budget.id]
      );

      lines = lineResult.rows;
    }

    const itemsResult = await pool.query(
      `SELECT
         i.*,
         l.tt_code,
         l.object_name,
         l.region,
         l.address,
         l.payment_due_text,
         l.budget_comment,
         l.base_f1,
         l.base_f2,
         l.budget_f1,
         l.budget_f2,
         c.payment_terms,
         c.critical_terms
       FROM rent_calendar_items i
       JOIN rent_budget_lines l
         ON l.id = i.budget_line_id
       LEFT JOIN rent_contracts c
         ON c.id = i.contract_id
       WHERE (
         i.due_date >= $1::date
         AND i.due_date < ($1::date + INTERVAL '1 month')
       )
       OR i.original_month = $2
       ORDER BY i.due_date, l.tt_code, i.contract_id, i.form, i.id`,
      [`${month}-01`, month]
    );

    const quotaResult = await pool.query(
      `SELECT
         week_start::text AS week_start,
         amount
       FROM rent_calendar_quota
       WHERE week_start >= ($1::date - INTERVAL '7 days')
         AND week_start < ($1::date + INTERVAL '1 month')
       ORDER BY week_start`,
      [`${month}-01`]
    );

    return res.json({
      ok: true,
      budgetStatus: budget?.status || null,
      weeks: rentBudgetWeeks(month),
      lines,
      items: itemsResult.rows,
      quotas: quotaResult.rows
    });
  } catch (error) {
    next(error);
  }
});

// ========================================
// ЗБЕРЕЖЕННЯ ТИЖНЕВОЇ КВОТИ
// ========================================

app.put(
  "/api/calendar/quota/:date",
  async (req, res, next) => {
    const date = req.params.date;
    const amount = calendarMoneyInt(req.body?.amount);

    if (
      !calendarValidDate(date) ||
      calendarMonday(date) !== date ||
      amount === null
    ) {
      return res.status(400).json({
        ok: false,
        error: "Перевірте дату понеділка та суму квоти"
      });
    }

    try {
      await pool.query(
        `INSERT INTO rent_calendar_quota (
           week_start,
           amount,
           updated_by
         )
         VALUES ($1,$2,$3)
         ON CONFLICT (week_start)
         DO UPDATE SET
           amount = EXCLUDED.amount,
           updated_by = EXCLUDED.updated_by,
           updated_at = NOW()`,
        [date, amount / 100, req.rentUser.id]
      );

      res.json({ ok: true });
    } catch (error) {
      next(error);
    }
  }
);

// ========================================
// АВТОМАТИЧНА ПРОПОЗИЦІЯ РОЗПОДІЛУ КВОТИ
// ========================================

app.post(
  "/api/calendar/week/:date/allocate",
  async (req, res, next) => {
    const date = req.params.date;

    if (
      !calendarValidDate(date) ||
      calendarMonday(date) !== date
    ) {
      return res.status(400).json({
        ok: false,
        error: "Некоректний тиждень"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const quota = await client.query(
        `SELECT amount
         FROM rent_calendar_quota
         WHERE week_start = $1
         FOR UPDATE`,
        [date]
      );

      if (!quota.rowCount) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error: "Спочатку внесіть квоту"
        });
      }

      const rows = await client.query(
        `SELECT i.*, c.critical_terms
         FROM rent_calendar_items i
         LEFT JOIN rent_contracts c
           ON c.id = i.contract_id
         WHERE i.due_date >= $1::date
           AND i.due_date < ($1::date + INTERVAL '7 days')
         ORDER BY i.due_date, i.contract_id, i.form, i.id
         FOR UPDATE OF i`,
        [date]
      );

      const protectedSum = rows.rows
        .filter(r => r.manually_funded || r.confirmed_at)
        .reduce(
          (sum, r) =>
            sum + Math.round(Number(r.funded) * 100),
          0
        );

      let available =
        Math.round(Number(quota.rows[0].amount) * 100) -
        protectedSum;

      if (available < 0) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error: "Квота менша за вручну розподілені суми"
        });
      }

      const sorted = rows.rows
        .filter(r => !r.manually_funded && !r.confirmed_at)
        .sort((a, b) => {
          const movable = r =>
            calendarMovable(r.critical_terms);

          return (
            Number(movable(a)) - Number(movable(b)) ||
            calendarIso(a.due_date)
              .localeCompare(calendarIso(b.due_date)) ||
            a.id - b.id
          );
        });

      for (const row of sorted) {
        const cents = Math.round(
          Number(row.amount) * 100
        );

        const funded = cents <= available
          ? cents
          : 0;

        available -= funded;

        await client.query(
          `UPDATE rent_calendar_items
           SET funded = $2
           WHERE id = $1`,
          [row.id, funded / 100]
        );
      }

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

// ========================================
// РУЧНЕ ФІНАНСУВАННЯ ПЛАТЕЖУ
// ========================================

app.patch(
  "/api/calendar/items/:id/funded",
  async (req, res, next) => {
    const id = Number(req.params.id);
    const cents = calendarMoneyInt(req.body?.amount);

    if (
      !Number.isSafeInteger(id) ||
      id < 1 ||
      cents === null
    ) {
      return res.status(400).json({
        ok: false,
        error: "Некоректна сума"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const found = await client.query(
        `SELECT *
         FROM rent_calendar_items
         WHERE id = $1
         FOR UPDATE`,
        [id]
      );

      if (!found.rowCount || found.rows[0].confirmed_at) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error: "Платіж не знайдено або тиждень підтверджено"
        });
      }

      const item = found.rows[0];
      const week = calendarMonday(
        calendarIso(item.due_date)
      );

      const quota = await client.query(
        `SELECT amount
         FROM rent_calendar_quota
         WHERE week_start = $1
         FOR UPDATE`,
        [week]
      );

      if (!quota.rowCount) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error: "Спочатку введіть квоту тижня"
        });
      }

      const used = await client.query(
        `SELECT COALESCE(SUM(funded), 0) AS amount
         FROM rent_calendar_items
         WHERE due_date >= $1::date
           AND due_date < ($1::date + INTERVAL '7 days')
           AND id <> $2`,
        [week, id]
      );

      if (
        cents > Math.round(Number(item.amount) * 100) ||
        cents +
          Math.round(Number(used.rows[0].amount) * 100) >
          Math.round(Number(quota.rows[0].amount) * 100)
      ) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error: "Перевищення залишку платежу або квоти"
        });
      }

      await client.query(
        `UPDATE rent_calendar_items
         SET funded = $2,
             manually_funded = TRUE
         WHERE id = $1`,
        [id, cents / 100]
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

// ========================================
// ПОВНЕ АБО ЧАСТКОВЕ ПЕРЕНЕСЕННЯ
// ========================================

app.post(
  "/api/calendar/items/:id/move",
  async (req, res, next) => {
    const id = Number(req.params.id);
    const cents = calendarMoneyInt(req.body?.amount);
    const date = req.body?.date;

    if (
      !Number.isSafeInteger(id) ||
      id < 1 ||
      !cents ||
      !calendarValidDate(date)
    ) {
      return res.status(400).json({
        ok: false,
        error: "Перевірте суму та дату"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const found = await client.query(
        `SELECT i.*, c.critical_terms
         FROM rent_calendar_items i
         LEFT JOIN rent_contracts c
           ON c.id = i.contract_id
         WHERE i.id = $1
         FOR UPDATE OF i`,
        [id]
      );

      const item = found.rows[0];

      if (!item || item.confirmed_at) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error: "Платіж уже підтверджено або не знайдено"
        });
      }

      if (!calendarMovable(item.critical_terms)) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error: "У договорі не підтверджено можливість перенесення"
        });
      }

      if (
        cents > Math.round(Number(item.amount) * 100) ||
        date === calendarIso(item.due_date)
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          ok: false,
          error: "Сума завелика або дата не змінюється"
        });
      }

      const remaining =
        (
          Math.round(Number(item.amount) * 100) -
          cents
        ) / 100;

      const oldFunded = Math.round(
        Number(item.funded) * 100
      );

      await client.query(
        `UPDATE rent_calendar_items
         SET amount = $2,
             funded = $3
         WHERE id = $1`,
        [
          id,
          remaining,
          Math.min(
            oldFunded,
            Math.round(remaining * 100)
          ) / 100
        ]
      );

      const created = await client.query(
        `INSERT INTO rent_calendar_items (
           budget_line_id,
           contract_id,
           form,
           original_month,
           original_week,
           original_amount,
           amount,
           due_date,
           initial_date,
           parent_id
         )
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         RETURNING id`,
        [
          item.budget_line_id,
          item.contract_id,
          item.form,
          item.original_month,
          item.original_week,
          0,
          cents / 100,
          date,
          calendarIso(item.initial_date),
          id
        ]
      );

      await client.query(
        `INSERT INTO rent_calendar_events (
           item_id,
           action,
           details,
           actor_id
         )
         VALUES ($1,'move',$2,$3)`,
        [
          id,
          JSON.stringify({
            newItemId: created.rows[0].id,
            amount: cents / 100,
            from: calendarIso(item.due_date),
            to: date
          }),
          req.rentUser.id
        ]
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
        newItemId: created.rows[0].id
      });
    } catch (error) {
      await client.query("ROLLBACK");
      next(error);
    } finally {
      client.release();
    }
  }
);

// ========================================
// ПІДТВЕРДЖЕННЯ ФАКТИЧНИХ ОПЛАТ
// ========================================

app.post(
  "/api/calendar/week/:date/confirm",
  async (req, res, next) => {
    const date = req.params.date;
    const payments = req.body?.payments;

    if (
      !calendarValidDate(date) ||
      calendarMonday(date) !== date ||
      !Array.isArray(payments)
    ) {
      return res.status(400).json({
        ok: false,
        error: "Некоректні фактичні оплати"
      });
    }

    if (!calendarWeekFinished(date)) {
      return res.status(409).json({
        ok: false,
        error: "Факт підтверджуємо тільки після завершення тижня"
      });
    }

    const map = new Map();

    for (const payment of payments) {
      const cents = calendarMoneyInt(payment.actual);
      const id = Number(payment.id);

      if (
        !Number.isSafeInteger(id) ||
        id < 1 ||
        cents === null ||
        map.has(id)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Перевірте фактичні суми"
        });
      }

      map.set(id, cents);
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const rows = await client.query(
        `SELECT *
         FROM rent_calendar_items
         WHERE due_date >= $1::date
           AND due_date < ($1::date + INTERVAL '7 days')
           AND amount > 0
         FOR UPDATE`,
        [date]
      );

      if (
        rows.rows.some(r =>
          map.get(Number(r.id)) >
          Math.round(Number(r.amount) * 100)
        )
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          ok: false,
          error: "Факт не може перевищувати зобов'язання за платежем"
        });
      }

      if (
        rows.rows.some(r => r.confirmed_at) ||
        rows.rowCount !== map.size ||
        rows.rows.some(r => !map.has(Number(r.id)))
      ) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error: "Перелік платежів змінився або тиждень уже підтверджений. Оновіть календар."
        });
      }

      for (const row of rows.rows) {
        await client.query(
          `UPDATE rent_calendar_items
           SET actual = $2,
               confirmed_at = NOW(),
               confirmed_by = $3
           WHERE id = $1`,
          [
            row.id,
            map.get(Number(row.id)) / 100,
            req.rentUser.id
          ]
        );
      }

      await client.query(
        `INSERT INTO rent_calendar_events (
           item_id,
           action,
           details,
           actor_id
         )
         VALUES (NULL,'confirm_week',$1,$2)`,
        [
          JSON.stringify({
            week: date,
            count: rows.rowCount
          }),
          req.rentUser.id
        ]
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
        count: rows.rowCount
      });
    } catch (error) {
      await client.query("ROLLBACK");
      next(error);
    } finally {
      client.release();
    }
  }
);

async function initializeRentBudget() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS rent_budgets (
      id BIGSERIAL PRIMARY KEY,
      budget_month VARCHAR(7) NOT NULL UNIQUE,
      status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'approved')),
      created_by BIGINT REFERENCES rent_users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      approved_by BIGINT REFERENCES rent_users(id) ON DELETE SET NULL,
      approved_at TIMESTAMPTZ,
      revision INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS rent_budget_lines (
      id BIGSERIAL PRIMARY KEY,
      budget_id BIGINT NOT NULL
        REFERENCES rent_budgets(id) ON DELETE CASCADE,
      contract_id VARCHAR(30) NOT NULL,
      tt_code TEXT,
      object_name TEXT,
      address TEXT,
      region TEXT,
      end_date DATE,
      payment_due_text TEXT,
      base_f1 NUMERIC(14,2) NOT NULL DEFAULT 0,
      base_f2 NUMERIC(14,2) NOT NULL DEFAULT 0,
      budget_f1 NUMERIC(14,2) NOT NULL DEFAULT 0,
      budget_f2 NUMERIC(14,2) NOT NULL DEFAULT 0,
      weeks_f1 JSONB NOT NULL DEFAULT '[]'::jsonb,
      weeks_f2 JSONB NOT NULL DEFAULT '[]'::jsonb,
      needs_review BOOLEAN NOT NULL DEFAULT FALSE,
      budget_comment TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(budget_id, contract_id)
    );

    CREATE INDEX IF NOT EXISTS idx_rent_budget_lines_month
      ON rent_budget_lines(budget_id);
  `);

  await pool.query(`
    ALTER TABLE rent_budgets
      ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'draft',
      ADD COLUMN IF NOT EXISTS approved_by BIGINT REFERENCES rent_users(id) ON DELETE SET NULL,
      ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 1;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS rent_budget_status_history (
      id BIGSERIAL PRIMARY KEY,
      budget_id BIGINT NOT NULL
        REFERENCES rent_budgets(id) ON DELETE CASCADE,
      from_status TEXT,
      to_status TEXT NOT NULL,
      changed_by BIGINT REFERENCES rent_users(id) ON DELETE SET NULL,
      changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

function rentBudgetWeeks(month) {
  const [year, number] = month.split("-").map(Number);
  const days = new Date(Date.UTC(year, number, 0)).getUTCDate();
  const weeks = [];
  let first = 1;

  while (first <= days) {
    const date = new Date(Date.UTC(year, number - 1, first));
    const dayOfWeek = (date.getUTCDay() + 6) % 7;
    const last = Math.min(days, first + 6 - dayOfWeek);

    weeks.push({
      from: first,
      to: last,
      label: `${String(first).padStart(2, "0")}–${String(last).padStart(2, "0")}`
    });

    first = last + 1;
  }

  return weeks;
}


function rentBudgetDefaultWeeks(
  dueText, amountF1, amountF2, weeks, month
) {
  const f1 = weeks.map(() => 0);
  const f2 = weeks.map(() => 0);

  const source = String(dueText || "")
    .toLowerCase()
    .replace(/[’ʼ]/g, "'")
    .replace(/\s+/g, " ")
    .trim();

  const [year, monthNumber] = month.split("-").map(Number);
  const daysInMonth = new Date(
    Date.UTC(year, monthNumber, 0)
  ).getUTCDate();

  let firstDay = null;

  // "з 15 до 20", "з 20 по 30", "15-20", "15–20"
  const range = source.match(
    /(?:^|[^\d])(?:з\s*)?(\d{1,2})\s*(?:-|–|—|до|по)\s*(\d{1,2})(?!\d)/u
  );

  if (range) {
    const from = Number(range[1]);
    const to = Number(range[2]);

    if (
      from >= 1 &&
      to <= daysInMonth &&
      from <= to
    ) {
      firstDay = from;
    }
  }

  // "до 10", "до 10-го", "не пізніше 10 числа".
  // Плануємо на перший тиждень місяця.
  if (firstDay === null) {
    const deadline = source.match(
      /(?:до|не пізніше)\s*(\d{1,2})(?:\s*[-–]?\s*(?:го|ого|числа))?/u
    );

    if (
      deadline &&
      Number(deadline[1]) >= 1 &&
      Number(deadline[1]) <= daysInMonth
    ) {
      firstDay = 1;
    }
  }

  // "20", "20 числа", "20-го числа", "20.10"
  if (firstDay === null) {
    const exact = source.match(
      /^(?:з\s*)?(\d{1,2})(?:[-–]?(?:го|ого))?(?:\s*числа)?(?:\s*[.,]\s*\d{1,2})?(?:\s|$)/u
    );

    if (
      exact &&
      Number(exact[1]) >= 1 &&
      Number(exact[1]) <= daysInMonth
    ) {
      firstDay = Number(exact[1]);
    }
  }

  let weekIndex = -1;

  if (firstDay !== null) {
    const date = new Date(
      Date.UTC(year, monthNumber - 1, firstDay)
    );

    const dayOfWeek = date.getUTCDay();

    // П'ятниця: план переносимо на наступний тиждень.
    // Понеділок: залишаємо в поточному тижні.
    const plannedDay = dayOfWeek === 5
      ? firstDay + 3
      : firstDay;

    if (plannedDay <= daysInMonth) {
      weekIndex = weeks.findIndex(
        week =>
          plannedDay >= week.from &&
          plannedDay <= week.to
      );
    }
  }

  if (weekIndex >= 0) {
    f1[weekIndex] = Number(amountF1 || 0);
    f2[weekIndex] = Number(amountF2 || 0);
  }

  return {
    f1,
    f2,
    needsReview:
      weekIndex < 0 &&
      (
        Number(amountF1 || 0) !== 0 ||
        Number(amountF2 || 0) !== 0
      )
  };
}

function rentBudgetValidMonth(month) {
  return /^\d{4}-(0[1-9]|1[0-2])$/.test(String(month || "")) &&
    Number(String(month).slice(0, 4)) >= 2000;
}

app.use("/api/budget", rentRequireSession, (req, res, next) => {
  if (req.rentUser.must_change_password) {
    return res.status(403).json({
      ok: false,
      error: "Спочатку змініть тимчасовий пароль"
    });
  }

  if (req.method !== "GET" &&
      !["admin", "editor"].includes(req.rentUser.role)) {
    return res.status(403).json({
      ok: false,
      error: "Недостатньо прав для зміни бюджету"
    });
  }

  next();
});

app.get("/api/budget/:month", async (req, res, next) => {
  try {
    const month = req.params.month;

    if (!rentBudgetValidMonth(month)) {
      return res.status(400).json({
        ok: false,
        error: "Некоректний місяць"
      });
    }

    const budget = await pool.query(
      "SELECT * FROM rent_budgets WHERE budget_month = $1",
      [month]
    );

    if (!budget.rowCount) {
      return res.json({
        ok: true,
        exists: false,
        weeks: rentBudgetWeeks(month),
        lines: []
      });
    }

    const lines = await pool.query(
      `SELECT
         l.*,
         c.rent_f1 AS current_f1,
         c.rent_f2 AS current_f2,
         c.payment_terms AS current_payment_terms,
         c.archived_at AS current_archived_at
       FROM rent_budget_lines l
       LEFT JOIN rent_contracts c ON c.id = l.contract_id
       WHERE l.budget_id = $1
       ORDER BY l.tt_code NULLS LAST, l.contract_id`,
      [budget.rows[0].id]
    );

    res.json({
      ok: true,
      exists: true,
      budget: budget.rows[0],
      weeks: rentBudgetWeeks(month),
      lines: lines.rows
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/budget/:month/create", async (req, res, next) => {
  const month = req.params.month;

  if (!rentBudgetValidMonth(month)) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний місяць"
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const created = await client.query(
      `INSERT INTO rent_budgets (budget_month, created_by)
       VALUES ($1, $2)
       ON CONFLICT (budget_month) DO NOTHING
       RETURNING id`,
      [month, req.rentUser.id]
    );

    if (!created.rowCount) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        ok: false,
        error: "Бюджет цього місяця вже створено"
      });
    }

    const budgetId = created.rows[0].id;

    await client.query(
      `INSERT INTO rent_budget_status_history
         (budget_id, from_status, to_status, changed_by)
       VALUES ($1, NULL, 'draft', $2)`,
      [budgetId, req.rentUser.id]
    );

    const weeks = rentBudgetWeeks(month);

    const contracts = await client.query(`
      SELECT
        id, tt_code, object_name, address, region, end_date,
        rent_f1, rent_f2, payment_terms
      FROM rent_contracts
      WHERE archived_at IS NULL
      ORDER BY id
    `);

    for (const contract of contracts.rows) {
      const f1 = Number(contract.rent_f1 || 0);
      const f2 = Number(contract.rent_f2 || 0);

      const dueText = String(
        contract.payment_terms?.["Строк/дата оплати"] || ""
      );

      const allocation = rentBudgetDefaultWeeks(
        dueText, f1, f2, weeks, month
      );

      await client.query(
        `INSERT INTO rent_budget_lines (
          budget_id, contract_id, tt_code, object_name,
          address, region, end_date, payment_due_text,
          base_f1, base_f2, budget_f1, budget_f2,
          weeks_f1, weeks_f2, needs_review
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8,
          $9, $10, $11, $12, $13::jsonb, $14::jsonb, $15
        )`,
        [
          budgetId,
          contract.id,
          contract.tt_code,
          contract.object_name,
          contract.address,
          contract.region,
          contract.end_date,
          dueText,
          f1, f2, f1, f2,
          JSON.stringify(allocation.f1),
          JSON.stringify(allocation.f2),
          allocation.needsReview
        ]
      );
    }

    await client.query("COMMIT");

    res.status(201).json({
      ok: true,
      created: contracts.rowCount
    });
  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

app.patch("/api/budget/lines/:id", async (req, res, next) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({
        ok: false,
        error: "Некоректний рядок бюджету"
      });
    }

    const existing = await pool.query(
      `SELECT l.*, b.budget_month
       FROM rent_budget_lines l
       JOIN rent_budgets b ON b.id = l.budget_id
       WHERE l.id = $1`,
      [id]
    );

    if (!existing.rowCount) {
      return res.status(404).json({
        ok: false,
        error: "Рядок бюджету не знайдено"
      });
    }

    const line = existing.rows[0];
    const weeks = rentBudgetWeeks(line.budget_month);

    function amount(value) {
      const number = Number(value);

      return Number.isFinite(number) &&
        number >= 0 &&
        Math.round(number * 100) === number * 100
        ? number : null;
    }

    const f1 = amount(req.body.budget_f1);
    const f2 = amount(req.body.budget_f2);
    const weeksF1 = req.body.weeks_f1;
    const weeksF2 = req.body.weeks_f2;

    if (
      f1 === null || f2 === null ||
      !Array.isArray(weeksF1) ||
      !Array.isArray(weeksF2) ||
      weeksF1.length !== weeks.length ||
      weeksF2.length !== weeks.length ||
      [...weeksF1, ...weeksF2].some(value => amount(value) === null)
    ) {
      return res.status(400).json({
        ok: false,
        error: "Перевірте суми та розподіл за тижнями"
      });
    }

    const comment = String(req.body.budget_comment || "").trim();

    if (comment.length > 2000) {
      return res.status(400).json({
        ok: false,
        error: "Коментар занадто довгий"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const budgetState = await client.query(
        `SELECT status
         FROM rent_budgets
         WHERE id = $1
         FOR UPDATE`,
        [line.budget_id]
      );

      if (
        !budgetState.rowCount ||
        budgetState.rows[0].status !== "draft"
      ) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error: "Затверджений бюджет не можна редагувати"
        });
      }

      await client.query(
        `UPDATE rent_budget_lines
         SET budget_f1 = $2,
             budget_f2 = $3,
             weeks_f1 = $4::jsonb,
             weeks_f2 = $5::jsonb,
             budget_comment = $6,
             needs_review = FALSE,
             updated_at = NOW()
         WHERE id = $1`,
        [
          id, f1, f2,
          JSON.stringify(weeksF1.map(Number)),
          JSON.stringify(weeksF2.map(Number)),
          comment || null
        ]
      );

      await client.query("COMMIT");

      res.json({ ok: true });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    next(error);
  }
});


app.post("/api/budget/:month/reallocate", async (req, res, next) => {
  const month = req.params.month;

  if (!rentBudgetValidMonth(month)) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний місяць бюджету"
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const budgetResult = await client.query(
      `SELECT id, status
       FROM rent_budgets
       WHERE budget_month = $1
       FOR UPDATE`,
      [month]
    );

    if (!budgetResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        ok: false,
        error: "Бюджет не знайдено"
      });
    }

    const budget = budgetResult.rows[0];

    if (budget.status !== "draft") {
      await client.query("ROLLBACK");
      return res.status(409).json({
        ok: false,
        error: "Оновлювати платежі можна лише в чернетці"
      });
    }

    const weeks = rentBudgetWeeks(month);

    const result = await client.query(
      `SELECT *
       FROM rent_budget_lines
       WHERE budget_id = $1
         AND needs_review = TRUE
       FOR UPDATE`,
      [budget.id]
    );

    let updated = 0;
    let skipped = 0;
    let unresolved = 0;

    for (const line of result.rows) {
      const oldF1 = line.weeks_f1;
      const oldF2 = line.weeks_f2;

      // Не чіпаємо рядки, де вже щось рознесено.
      const hasAllocation =
        !Array.isArray(oldF1) ||
        !Array.isArray(oldF2) ||
        oldF1.length !== weeks.length ||
        oldF2.length !== weeks.length ||
        [...oldF1, ...oldF2].some(value => Number(value) !== 0);

      // Не чіпаємо змінені вручну бюджетні суми.
      const hasChangedAmounts =
        Number(line.budget_f1) !== Number(line.base_f1) ||
        Number(line.budget_f2) !== Number(line.base_f2);

      // Не чіпаємо рядки з коментарями працівника.
      const hasComment = Boolean(
        String(line.budget_comment || "").trim()
      );

      if (hasAllocation || hasChangedAmounts || hasComment) {
        skipped++;
        continue;
      }

      const allocation = rentBudgetDefaultWeeks(
        line.payment_due_text,
        Number(line.budget_f1),
        Number(line.budget_f2),
        weeks,
        month
      );

      if (allocation.needsReview) {
        unresolved++;
        continue;
      }

      await client.query(
        `UPDATE rent_budget_lines
         SET weeks_f1 = $2::jsonb,
             weeks_f2 = $3::jsonb,
             needs_review = FALSE,
             updated_at = NOW()
         WHERE id = $1`,
        [
          line.id,
          JSON.stringify(allocation.f1),
          JSON.stringify(allocation.f2)
        ]
      );

      updated++;
    }

    await client.query("COMMIT");

    res.json({
      ok: true,
      updated,
      skipped,
      unresolved,
      message:
        `Автоматично рознесено: ${updated}. ` +
        `Пропущено через ручні зміни: ${skipped}. ` +
        `Потребують перевірки: ${unresolved}.`
    });
  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});


app.get("/api/budget/:month/export-excel", async (req, res, next) => {
  try {
    const month = req.params.month;

    if (!rentBudgetValidMonth(month)) {
      return res.status(400).json({
        ok: false,
        error: "Некоректний місяць бюджету"
      });
    }

    const budgetResult = await pool.query(
      `SELECT id, status
       FROM rent_budgets
       WHERE budget_month = $1`,
      [month]
    );

    if (!budgetResult.rowCount) {
      return res.status(404).json({
        ok: false,
        error: "Бюджет не знайдено"
      });
    }

    const budget = budgetResult.rows[0];
    const weeks = rentBudgetWeeks(month);

    const linesResult = await pool.query(
      `SELECT *
       FROM rent_budget_lines
       WHERE budget_id = $1
       ORDER BY tt_code NULLS LAST, contract_id`,
      [budget.id]
    );

    const book = new ExcelJS.Workbook();
    book.creator = "Управління орендою";

    const sheet = book.addWorksheet("Бюджет оренди", {
      views: [{
        state: "frozen",
        xSplit: 3,
        ySplit: 5
      }]
    });

    const columns = [
      { header: "ТТ", width: 11 },
      { header: "ID", width: 17 },
      { header: "Область / адреса", width: 48 },
      { header: "Строк оплати", width: 29 },
      { header: "Ф1 дог., грн", width: 18 },
      { header: "Ф2 дог., грн", width: 18 },
      { header: "Ф1 бюджет, грн", width: 19 },
      { header: "Ф2 бюджет, грн", width: 19 },
      { header: "Всього, грн", width: 19 }
    ];

    for (const week of weeks) {
      columns.push(
        { header: "Ф1", width: 18 },
        { header: "Ф2", width: 18 }
      );
    }

    columns.push({ header: "Коментар / перевірка", width: 45 });

    sheet.columns = columns.map(column => ({
      width: column.width
    }));

    const lastColumn = columns.length;
    const commentColumn = lastColumn;

    const letter = number => sheet.getColumn(number).letter;

    sheet.mergeCells(1, 1, 1, lastColumn);
    sheet.getCell("A1").value =
      `БЮДЖЕТ ОРЕНДИ ЗА ${month.slice(5)}.${month.slice(0, 4)}`;

    sheet.getRow(1).height = 37;
    sheet.getCell("A1").font = {
      bold: true,
      size: 17,
      color: { argb: "FFFFFFFF" }
    };
    sheet.getCell("A1").fill = {
      type: "pattern",
      pattern: "solid",
      fgColor: { argb: "FF233B5A" }
    };
    sheet.getCell("A1").alignment = {
      vertical: "middle",
      horizontal: "center"
    };

    sheet.mergeCells(2, 1, 2, lastColumn);
    sheet.getCell("A2").value =
      `Статус: ${
        budget.status === "approved" ? "Затверджений" : "Чернетка"
      }  |  Договорів: ${linesResult.rowCount}`;

    sheet.getCell("A2").font = {
      bold: true,
      size: 11,
      color: { argb: "FF30425B" }
    };
    sheet.getRow(2).height = 28;

    // Заголовки основних колонок.
    for (let col = 1; col <= 9; col++) {
      sheet.mergeCells(4, col, 5, col);
      sheet.getCell(4, col).value = columns[col - 1].header;
    }

    // Кожен тиждень має дві підколонки: Ф1 і Ф2.
    weeks.forEach((week, index) => {
      const col = 10 + index * 2;

      sheet.mergeCells(4, col, 4, col + 1);

      sheet.getCell(4, col).value =
        `Тиждень ${index + 1}: ${week.label}`;

      sheet.getCell(5, col).value = "Ф1";
      sheet.getCell(5, col + 1).value = "Ф2";
    });

    sheet.mergeCells(4, commentColumn, 5, commentColumn);
    sheet.getCell(4, commentColumn).value =
      "Коментар / перевірка";

    sheet.getRow(4).height = 34;
    sheet.getRow(5).height = 27;

    const orange = "FFFFF2E4";
    const green = "FFEAF6ED";
    const orangeHeader = "FFF8E5D1";
    const greenHeader = "FFDCEFE1";
    const moneyFormat = '#,##0.00';

    for (let row = 4; row <= 5; row++) {
      for (let col = 1; col <= lastColumn; col++) {
        const cell = sheet.getCell(row, col);

        cell.font = {
          bold: true,
          color: { argb: "FF30425B" }
        };

        cell.alignment = {
          horizontal: "center",
          vertical: "middle",
          wrapText: true
        };

        cell.fill = {
          type: "pattern",
          pattern: "solid",
          fgColor: { argb: "FFEAF0F7" }
        };

        cell.border = {
          bottom: {
            style: "thin",
            color: { argb: "FFDCE5EF" }
          },
          right: {
            style: "thin",
            color: { argb: "FFDCE5EF" }
          }
        };
      }
    }

    weeks.forEach((week, index) => {
      const color = index % 2 === 0
        ? orangeHeader : greenHeader;

      for (const row of [4, 5]) {
        for (const col of [10 + index * 2, 11 + index * 2]) {
          sheet.getCell(row, col).fill = {
            type: "pattern",
            pattern: "solid",
            fgColor: { argb: color }
          };
        }
      }
    });

    // Дані договорів.
    for (const line of linesResult.rows) {
      const f1 = Number(line.budget_f1 || 0);
      const f2 = Number(line.budget_f2 || 0);

      const values = [
        line.tt_code || "",
        line.contract_id,
        [line.region, line.address].filter(Boolean).join(" · "),
        line.payment_due_text || "",
        Number(line.base_f1 || 0),
        Number(line.base_f2 || 0),
        f1,
        f2,
        f1 + f2
      ];

      weeks.forEach((week, index) => {
        values.push(
          Number(line.weeks_f1?.[index] || 0),
          Number(line.weeks_f2?.[index] || 0)
        );
      });

      values.push(line.budget_comment || "");

      const row = sheet.addRow(values);
      row.height = 34;

      row.eachCell({ includeEmpty: true }, (cell, col) => {
        cell.alignment = {
          vertical: "middle",
          wrapText: col === 3 || col === 4 ||
            col === commentColumn
        };

        cell.border = {
          bottom: {
            style: "hair",
            color: { argb: "FFE1E8F1" }
          },
          right: {
            style: "hair",
            color: { argb: "FFE1E8F1" }
          }
        };

        cell.fill = {
          type: "pattern",
          pattern: "solid",
          fgColor: {
            argb: row.number % 2 === 0
              ? "FFF7F9FC" : "FFFFFFFF"
          }
        };

        if (col >= 5 && col < commentColumn) {
          cell.numFmt = moneyFormat;
        }
      });

      weeks.forEach((week, index) => {
        const color = index % 2 === 0 ? orange : green;

        for (const col of [10 + index * 2, 11 + index * 2]) {
          row.getCell(col).fill = {
            type: "pattern",
            pattern: "solid",
            fgColor: { argb: color }
          };
        }
      });

      if (line.needs_review) {
        row.getCell(commentColumn).value =
          [line.budget_comment, "Потребує перевірки"]
            .filter(Boolean).join("\n");
      }
    }

    // Підсумковий рядок.
    const firstDataRow = 6;
    const lastDataRow = sheet.lastRow.number;
    const totalRow = sheet.addRow([]);

    sheet.mergeCells(totalRow.number, 1, totalRow.number, 4);
    totalRow.getCell(1).value = "РАЗОМ";
    totalRow.height = 32;

    for (let col = 5; col < commentColumn; col++) {
      const colLetter = letter(col);

      totalRow.getCell(col).value =
        lastDataRow >= firstDataRow
          ? {
              formula:
                `SUM(${colLetter}${firstDataRow}:` +
                `${colLetter}${lastDataRow})`
            }
          : 0;

      totalRow.getCell(col).numFmt = moneyFormat;
    }

    for (let col = 1; col <= lastColumn; col++) {
      const cell = totalRow.getCell(col);

      cell.font = {
        bold: true,
        color: { argb: "FF203956" }
      };
      cell.fill = {
        type: "pattern",
        pattern: "solid",
        fgColor: { argb: "FFDCE8F6" }
      };
      cell.alignment = {
        vertical: "middle",
        horizontal: col <= 4 ? "left" : "right"
      };
    }

    weeks.forEach((week, index) => {
      const color = index % 2 === 0
        ? orangeHeader : greenHeader;

      for (const col of [10 + index * 2, 11 + index * 2]) {
        totalRow.getCell(col).fill = {
          type: "pattern",
          pattern: "solid",
          fgColor: { argb: color }
        };
      }
    });

    sheet.autoFilter = {
      from: { row: 5, column: 1 },
      to: {
        row: Math.max(firstDataRow, lastDataRow),
        column: lastColumn
      }
    };

    book.calcProperties.fullCalcOnLoad = true;

    const buffer = await book.xlsx.writeBuffer();

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="rent_budget_${month}.xlsx"`
    );

    res.setHeader("Cache-Control", "no-store");

    return res.send(Buffer.from(buffer));
  } catch (error) {
    next(error);
  }
});

app.post("/api/budget/:month/approve", async (req, res, next) => {
  const month = req.params.month;

  if (!rentBudgetValidMonth(month)) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний місяць"
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT *
       FROM rent_budgets
       WHERE budget_month = $1
       FOR UPDATE`,
      [month]
    );

    if (!result.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        ok: false,
        error: "Бюджет не знайдено"
      });
    }

    const budget = result.rows[0];

    if (budget.status !== "draft") {
      await client.query("ROLLBACK");
      return res.status(409).json({
        ok: false,
        error: "Бюджет уже затверджено"
      });
    }

    const lines = await client.query(
      `SELECT contract_id, budget_f1, budget_f2,
              weeks_f1, weeks_f2, needs_review
       FROM rent_budget_lines
       WHERE budget_id = $1`,
      [budget.id]
    );

    if (!lines.rowCount) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        ok: false,
        error: "Неможливо затвердити порожній бюджет"
      });
    }

    const expectedWeeks = rentBudgetWeeks(month).length;

    const invalid = lines.rows.filter(line => {
      const f1 = Array.isArray(line.weeks_f1)
        ? line.weeks_f1 : [];
      const f2 = Array.isArray(line.weeks_f2)
        ? line.weeks_f2 : [];

      if (
        line.needs_review ||
        f1.length !== expectedWeeks ||
        f2.length !== expectedWeeks
      ) return true;

      const sum = values => {
        if (values.some(v => !Number.isFinite(Number(v)) ||
            Number(v) < 0)) return NaN;

        return Math.round(
          values.reduce((total, v) =>
            total + Math.round(Number(v) * 100), 0)
        );
      };

      return (
        sum(f1) !== Math.round(Number(line.budget_f1) * 100) ||
        sum(f2) !== Math.round(Number(line.budget_f2) * 100)
      );
    });

    if (invalid.length) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        ok: false,
        error:
          `Є ${invalid.length} договорів із нерознесеними ` +
          `платежами або неперевіреними строками оплати.`,
        contractIds: invalid.map(line => line.contract_id)
      });
    }

    await client.query(
      `UPDATE rent_budgets
       SET status = 'approved',
           approved_by = $2,
           approved_at = NOW()
       WHERE id = $1`,
      [budget.id, req.rentUser.id]
    );

    await client.query(
      `INSERT INTO rent_budget_status_history
         (budget_id, from_status, to_status, changed_by)
       VALUES ($1, 'draft', 'approved', $2)`,
      [budget.id, req.rentUser.id]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      status: "approved"
    });
  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

app.post("/api/budget/:month/reopen", async (req, res, next) => {
  if (req.rentUser.role !== "admin") {
    return res.status(403).json({
      ok: false,
      error: "Повернути бюджет у чернетку може лише адміністратор"
    });
  }

  const month = req.params.month;

  if (!rentBudgetValidMonth(month)) {
    return res.status(400).json({
      ok: false,
      error: "Некоректний місяць"
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT *
       FROM rent_budgets
       WHERE budget_month = $1
       FOR UPDATE`,
      [month]
    );

    if (!result.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        ok: false,
        error: "Бюджет не знайдено"
      });
    }

    const budget = result.rows[0];

    if (budget.status !== "approved") {
      await client.query("ROLLBACK");
      return res.status(409).json({
        ok: false,
        error: "Бюджет уже перебуває в чернетці"
      });
    }

    await client.query(
      `UPDATE rent_budgets
       SET status = 'draft',
           approved_by = NULL,
           approved_at = NULL,
           revision = revision + 1
       WHERE id = $1`,
      [budget.id]
    );

    await client.query(
      `INSERT INTO rent_budget_status_history
         (budget_id, from_status, to_status, changed_by)
       VALUES ($1, 'approved', 'draft', $2)`,
      [budget.id, req.rentUser.id]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      status: "draft",
      revision: Number(budget.revision) + 1
    });
  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

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
    await initializeRentBudget();
    await initializeRentCalendar();  
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
