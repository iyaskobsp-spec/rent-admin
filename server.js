require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

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
