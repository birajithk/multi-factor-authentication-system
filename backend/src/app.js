import express from "express";
import cookieParser from "cookie-parser";
import pool from "./config/database.js";
import sessionRoutes from "./routes/session.routes.js";
import authRoutes from "./routes/auth.routes.js";
import totpRoutes from "./routes/totp.routes.js";

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use("/api/auth", authRoutes);
app.use("/api/totp", totpRoutes);

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
        console.error(
            "Database connection error:",
            error
        );

        res.status(500).json({
            status: "error",
            database: "disconnected",
        });
    }
});

// ------------------------------------------------------------
// Full-session protected routes
// (/api/dashboard, /api/session, /api/session/logout)
// ------------------------------------------------------------

app.use("/api", sessionRoutes);

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

export default app;