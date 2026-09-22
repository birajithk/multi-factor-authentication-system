import express from "express";
import pool from "./config/database.js";
import authRoutes from "./routes/auth.routes.js";

const app = express();

app.use(express.json());
app.use("/api/auth", authRoutes);

app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    service: "SecureByte Backend",
  });
});

app.get("/api/health/db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");

    res.status(200).json({
      status: "ok",
      database: "connected",
      time: result.rows[0].now,
    });
  } catch (error) {
    console.error("Database connection error:", error);

    res.status(500).json({
      status: "error",
      database: "disconnected",
    });
  }
});

export default app;

// ------------------------------------------------------------
// Controlled request error handling
// ------------------------------------------------------------

app.use((error, req, res, next) => {
  // express.json() reports malformed JSON as a 400 SyntaxError.
  // Return controlled JSON instead of Express's development
  // HTML stack trace.
  if (
    error instanceof SyntaxError &&
    error.status === 400 &&
    "body" in error
  ) {
    return res.status(400).json({
      success: false,
      error: {
        type: "VALIDATION_ERROR",
        message: "Request body contains invalid JSON.",
      },
    });
  }

  // Do not return stack traces or internal details to the client.
  console.error("Unhandled request error:", error.message);

  return res.status(500).json({
    success: false,
    error: {
      type: "INTERNAL_ERROR",
      message: "The request could not be completed.",
    },
  });
});