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
