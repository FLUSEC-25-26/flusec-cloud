import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";

const app = express();
app.use(cors());
app.use(express.json({ limit: "5mb" }));

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || "flusec";
const PORT = Number(process.env.PORT || 8080);

if (!MONGODB_URI) {
  throw new Error("MONGODB_URI is required");
}

const client = new MongoClient(MONGODB_URI);
await client.connect();
const db = client.db(DB_NAME);
const batches = db.collection("HSD_findings");

// Basic health
app.get("/health", (req, res) => res.json({ ok: true }));

// Helper: verify GitHub token and get username
async function githubUsernameFromToken(token) {
  const r = await fetch("https://api.github.com/user", {
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept": "application/vnd.github+json",
      "User-Agent": "flusec-cloud"
    }
  });

  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`GitHub auth failed: HTTP ${r.status} ${text}`.trim());
  }

  const data = await r.json();
  if (!data?.login) throw new Error("GitHub response missing login"); 
  return data.login;
}

/**
 * POST /v1/findings
 * Headers:
 *   Authorization: Bearer <github_access_token>
 * Body:
 *   {
 *     "workspaceId": "optional-stable-id",
 *     "workspaceName": "optional",
 *     "extensionVersion": "0.0.1",
 *     "generatedAt": "ISO date",
 *     "findings": [ ... ]
 *   }
 */
app.post("/v1/findings", async (req, res) => {
  try {
    const auth = String(req.headers.authorization || "");
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (!token) return res.status(401).json({ ok: false, error: "Missing Bearer token" });

    const username = await githubUsernameFromToken(token);

    const body = req.body || {};
    const findings = Array.isArray(body.findings) ? body.findings : [];

    // Minimal validation
    if (!Array.isArray(findings)) {
      return res.status(400).json({ ok: false, error: "findings must be an array" });
    }

    const doc = {
      username,
      workspaceId: String(body.workspaceId || ""),
      workspaceName: String(body.workspaceName || ""),
      extensionVersion: String(body.extensionVersion || ""),
      generatedAt: String(body.generatedAt || new Date().toISOString()),
      receivedAt: new Date(),
      findings
    };

    const result = await batches.insertOne(doc);
    return res.json({ ok: true, username, batchId: result.insertedId.toString() });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.listen(PORT, () => {
  console.log(`flusec-cloud listening on http://localhost:${PORT}`);
});
