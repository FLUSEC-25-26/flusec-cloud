import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "5mb" }));

const MONGODBURI = process.env.MONGODBURI;
const DBNAME = process.env.DBNAME || "flusec";
const PORT = Number(process.env.PORT || 8082);

if (!MONGODBURI) {
  throw new Error("MONGODBURI is required");
}

console.log("[boot] MONGODBURI exists =", !!process.env.MONGODBURI);
console.log("[boot] DBNAME =", DBNAME);

const client = new MongoClient(MONGODBURI);
await client.connect();
const db = client.db(DBNAME);
const batches = db.collection("hardcoded_secrets_detection");

// Basic health
app.get("/health", (req, res) => res.json({ ok: true }));

// Helper: verify GitHub token and get username
async function githubUsernameFromToken(token) {
  const r = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "flusec-cloud",
    },
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
 * Normalize request body to a list of workspace payloads.
 * Supports:
 *  1) Multi-workspace:
 *     { extensionVersion, generatedAt, workspaces: [ {workspaceName, workspaceId, findings, ...}, ... ] }
 *  2) Flat (legacy):
 *     { workspaceName, workspaceId, extensionVersion, generatedAt, findings: [...] }
 */
function normalizeToWorkspaces(body) {
  // Multi-workspace
  if (body && Array.isArray(body.workspaces)) {
    return body.workspaces.map((w) => ({
      workspaceId: String(w?.workspaceId || ""),
      workspaceName: String(w?.workspaceName || ""),
      extensionVersion: String(body?.extensionVersion || w?.extensionVersion || ""),
      generatedAt: String(body?.generatedAt || w?.generatedAt || new Date().toISOString()),
      findings: Array.isArray(w?.findings) ? w.findings : [],
      findingsCount:
        typeof w?.findingsCount === "number" ? w.findingsCount : (Array.isArray(w?.findings) ? w.findings.length : 0),
      findingsFile: String(w?.findingsFile || ""),
    }));
  }

  // Flat legacy
  return [
    {
      workspaceId: String(body?.workspaceId || ""),
      workspaceName: String(body?.workspaceName || ""),
      extensionVersion: String(body?.extensionVersion || ""),
      generatedAt: String(body?.generatedAt || new Date().toISOString()),
      findings: Array.isArray(body?.findings) ? body.findings : [],
      findingsCount:
        typeof body?.findingsCount === "number" ? body.findingsCount : (Array.isArray(body?.findings) ? body.findings.length : 0),
      findingsFile: String(body?.findingsFile || ""),
    },
  ];
}

/**
 * POST /v1/findings
 * Headers:
 *   Authorization: Bearer <github_access_token>
 * Body (multi-workspace recommended):
 *   {
 *     "extensionVersion": "0.0.1",
 *     "generatedAt": "ISO",
 *     "workspaces": [
 *        { "workspaceName": "...", "workspaceId": "", "findings": [...], "findingsCount": 10, "findingsFile": "..." }
 *     ]
 *   }
 */
app.post("/v1/findings", async (req, res) => {
  try {
    const auth = String(req.headers.authorization || "");
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (!token) return res.status(401).json({ ok: false, error: "Missing Bearer token" });

    const username = await githubUsernameFromToken(token);

    const body = req.body || {};
    const workspacePayloads = normalizeToWorkspaces(body);

    // Minimal validation
    if (!Array.isArray(workspacePayloads) || workspacePayloads.length === 0) {
      return res.status(400).json({ ok: false, error: "Invalid payload" });
    }

    // Build docs (one per workspace)
    const docs = workspacePayloads.map((w) => ({
      username,
      workspaceId: w.workspaceId,
      workspaceName: w.workspaceName,
      extensionVersion: w.extensionVersion,
      generatedAt: w.generatedAt,
      receivedAt: new Date(),
      findingsFile: w.findingsFile,
      findingsCount: Number(w.findingsCount || 0),
      findings: Array.isArray(w.findings) ? w.findings : [],
    }));

    // Insert many docs
    const result = await batches.insertMany(docs);

    // Return helpful response
    const insertedIds = Object.values(result.insertedIds).map((id) => id.toString());
    const totalFindings = docs.reduce((sum, d) => sum + (d.findingsCount || 0), 0);

    return res.json({
      ok: true,
      username,
      batchesInserted: docs.length,
      totalFindings,
      batchIds: insertedIds,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.listen(PORT, () => {
  console.log(`flusec-cloud listening on http://localhost:${PORT}`);
});
