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

app.get("/api/contracts", async (req, res, next) => {
  try {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        error: "База даних не підключена"
      });
    }

    const result = await pool.query(`
      SELECT *
      FROM rent_contracts
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

    console.log("DATABASE TABLES: rent_contracts ready");
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
