/**
 * Pronnect - Standalone Zero-NPM Full-Stack Server
 * Runs with 100% pure Node.js built-ins
 * Clean inline CSS (zero external CDN scripts to prevent Chrome phishing false-positives)
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const url = require("url");

const PORT = process.env.PORT || 5000;
const DB_FILE = path.join(__dirname, "pronnect-local-data.json");
const ENCRYPTION_KEY_SECRET = "pronnect-standalone-secret-key-32b!";

// --- IN-MEMORY & PERSISTENT DATABASE ---
let db = {
  users: [],
  projects: [],
  members: [],
  joinRequests: [],
  tasks: [],
  polls: [],
  pollVotes: [],
  messages: [],
  media: [],
  notifications: [],
  sessions: {}, // token -> userId
};

// Load existing data
function loadDB() {
  if (fs.existsSync(DB_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));
      db = { ...db, ...data, sessions: {} };
    } catch (e) {
      console.error("Error loading local DB:", e);
    }
  } else {
    seedInitialData();
  }
}

function saveDB() {
  try {
    const toSave = { ...db, sessions: {} };
    fs.writeFileSync(DB_FILE, JSON.stringify(toSave, null, 2));
  } catch (e) {
    console.error("Error saving DB:", e);
  }
}

function seedInitialData() {
  // Clean fresh state — no demo projects pre-added
  saveDB();
}

// --- ENCRYPTION HELPERS (AES-256-GCM) ---
function deriveKey(secret) {
  return crypto.pbkdf2Sync(secret, ENCRYPTION_KEY_SECRET, 10000, 32, "sha256");
}

function encryptSettings(obj, userId) {
  try {
    const key = deriveKey(userId);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    let enc = cipher.update(JSON.stringify(obj), "utf8", "base64");
    enc += cipher.final("base64");
    const tag = cipher.getAuthTag().toString("base64");
    return JSON.stringify({ ciphertext: enc, iv: iv.toString("base64"), tag });
  } catch (e) {
    return null;
  }
}

// --- SSE CLIENTS FOR REALTIME ---
const sseClients = new Set();
function broadcastEvent(eventType, payload) {
  const data = JSON.stringify({ type: eventType, payload });
  sseClients.forEach((client) => {
    try {
      client.res.write(`data: ${data}\n\n`);
    } catch (e) {
      sseClients.delete(client);
    }
  });
}

// --- AUTH UTILS ---
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
}

function getUserFromReq(req) {
  const cookie = req.headers["cookie"] || "";
  const match = cookie.match(/pronnect_token=([^;]+)/);
  if (!match) return null;
  const token = match[1];
  const userId = db.sessions[token];
  if (!userId) return null;
  return db.users.find((u) => u.id === userId) || null;
}

// --- JSON BODY PARSER ---
function parseBody(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        resolve({});
      }
    });
  });
}

function sendJSON(res, data, status = 200, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    ...headers
  });
  res.end(JSON.stringify(data));
}

// --- HTTP REQUEST HANDLER ---
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;
  const user = getUserFromReq(req);

  // Security & CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");

  if (method === "OPTIONS") {
    res.writeHead(200);
    res.end();
    return;
  }

  // Real-time SSE Stream
  if (pathname === "/api/events") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    const client = { res, userId: user ? user.id : null };
    sseClients.add(client);
    req.on("close", () => sseClients.delete(client));
    return;
  }

  // --- API ROUTES ---

  // Auth: Current User
  if (pathname === "/api/auth/me") {
    if (!user) return sendJSON(res, { user: null });
    const { passwordHash, salt, ...safeUser } = user;
    return sendJSON(res, { user: safeUser });
  }

  // Full State Sync Endpoint (Client Mesh & Railway sync)
  if (pathname === "/api/sync") {
    if (method === "GET") {
      return sendJSON(res, { store: db });
    }
    if (method === "POST") {
      const incoming = await parseBody(req);
      if (incoming && typeof incoming === "object") {
        if (Array.isArray(incoming.projects)) db.projects = incoming.projects;
        if (Array.isArray(incoming.users)) db.users = incoming.users;
        if (Array.isArray(incoming.members)) db.members = incoming.members;
        if (Array.isArray(incoming.joinRequests)) db.joinRequests = incoming.joinRequests;
        if (Array.isArray(incoming.tasks)) db.tasks = incoming.tasks;
        if (Array.isArray(incoming.polls)) db.polls = incoming.polls;
        if (Array.isArray(incoming.pollVotes)) db.pollVotes = incoming.pollVotes;
        if (Array.isArray(incoming.messages)) db.messages = incoming.messages;
        if (Array.isArray(incoming.media)) db.media = incoming.media;
        saveDB();
        broadcastEvent("STATE_SYNC", { timestamp: Date.now() });
        return sendJSON(res, { success: true });
      }
    }
  }

  // Auth: Register
  if (pathname === "/api/auth/register" && method === "POST") {
    const { name, email, password, school } = await parseBody(req);
    if (!name || !email || !password) {
      return sendJSON(res, { error: "Name, email and password required" }, 400);
    }
    if (db.users.find((u) => u.email.toLowerCase() === email.toLowerCase())) {
      return sendJSON(res, { error: "Email already exists" }, 409);
    }
    const salt = crypto.randomBytes(16).toString("hex");
    const passwordHash = hashPassword(password, salt);
    const newUser = {
      id: "u_" + crypto.randomUUID().slice(0, 8),
      name,
      email,
      salt,
      passwordHash,
      school: school || "",
      bio: "",
      skills: [],
      githubUrl: "",
      createdAt: new Date().toISOString(),
    };
    db.users.push(newUser);
    saveDB();

    const token = crypto.randomUUID();
    db.sessions[token] = newUser.id;
    const { salt: s, passwordHash: ph, ...safe } = newUser;
    return sendJSON(res, { user: safe }, 201, {
      "Set-Cookie": `pronnect_token=${token}; Path=/; HttpOnly; SameSite=Lax`,
    });
  }

  // Auth: Login
  if (pathname === "/api/auth/login" && method === "POST") {
    const { email, password } = await parseBody(req);
    const u = db.users.find((x) => x.email.toLowerCase() === (email || "").toLowerCase());
    if (!u) return sendJSON(res, { error: "Invalid credentials" }, 401);
    const hash = hashPassword(password, u.salt);
    if (hash !== u.passwordHash) return sendJSON(res, { error: "Invalid credentials" }, 401);

    const token = crypto.randomUUID();
    db.sessions[token] = u.id;
    const { salt, passwordHash, ...safe } = u;
    return sendJSON(res, { user: safe }, 200, {
      "Set-Cookie": `pronnect_token=${token}; Path=/; HttpOnly; SameSite=Lax`,
    });
  }

  // Auth: Logout
  if (pathname === "/api/auth/logout" && method === "POST") {
    const cookie = req.headers["cookie"] || "";
    const match = cookie.match(/pronnect_token=([^;]+)/);
    if (match) delete db.sessions[match[1]];
    return sendJSON(res, { success: true }, 200, {
      "Set-Cookie": "pronnect_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    });
  }

  // Projects List / Explore
  if (pathname === "/api/projects" && method === "GET") {
    const { search, tag, school } = parsedUrl.query;
    let list = db.projects.filter((p) => p.visibility === "PUBLIC");

    if (tag) {
      list = list.filter((p) => p.tags.includes(tag));
    }
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((p) => p.name.toLowerCase().includes(q) || p.description.toLowerCase().includes(q));
    }
    if (school) {
      const q = school.toLowerCase();
      list = list.filter((p) => {
        const leader = db.users.find((u) => u.id === p.leaderId);
        return leader && leader.school.toLowerCase().includes(q);
      });
    }

    const enriched = list.map((p) => {
      const leader = db.users.find((u) => u.id === p.leaderId);
      const memberCount = db.members.filter((m) => m.projectId === p.id).length;
      return {
        ...p,
        leader: leader ? { id: leader.id, name: leader.name, school: leader.school } : null,
        _count: { members: memberCount },
      };
    });

    return sendJSON(res, { projects: enriched });
  }

  // Create Project
  if (pathname === "/api/projects" && method === "POST") {
    if (!user) return sendJSON(res, { error: "Unauthorized" }, 401);
    const { name, description, visibility, tags } = await parseBody(req);
    if (!name || !description) return sendJSON(res, { error: "Missing fields" }, 400);

    const newProj = {
      id: "p_" + crypto.randomUUID().slice(0, 8),
      name,
      description,
      visibility: visibility || "PUBLIC",
      tags: tags || [],
      leaderId: user.id,
      encryptedSettings: encryptSettings({ allowInvites: true, maxMembers: 50 }, user.id),
      inviteCode: crypto.randomUUID().slice(0, 8).toUpperCase(),
      createdAt: new Date().toISOString(),
    };

    db.projects.unshift(newProj);
    db.members.push({
      id: "m_" + crypto.randomUUID().slice(0, 8),
      projectId: newProj.id,
      userId: user.id,
      role: "LEADER",
      joinedAt: new Date().toISOString(),
    });
    saveDB();
    broadcastEvent("NEW_PROJECT", newProj);
    return sendJSON(res, { project: newProj }, 201);
  }

  // Project Details
  if (pathname.startsWith("/api/projects/") && !pathname.includes("/join-requests") && !pathname.includes("/tasks") && !pathname.includes("/polls") && !pathname.includes("/messages") && !pathname.includes("/media")) {
    const projId = pathname.split("/")[3];
    const proj = db.projects.find((p) => p.id === projId);
    if (!proj) return sendJSON(res, { error: "Not found" }, 404);

    const leader = db.users.find((u) => u.id === proj.leaderId);
    const members = db.members
      .filter((m) => m.projectId === proj.id)
      .map((m) => {
        const u = db.users.find((x) => x.id === m.userId);
        return {
          ...m,
          user: u ? { id: u.id, name: u.name, school: u.school, skills: u.skills, bio: u.bio } : null,
        };
      });

    const isMember = user ? members.some((m) => m.userId === user.id) : false;
    const isLeader = user ? proj.leaderId === user.id : false;

    return sendJSON(res, {
      project: {
        ...proj,
        leader: leader ? { id: leader.id, name: leader.name, school: leader.school } : null,
        members,
        _count: { members: members.length },
      },
      isMember,
      isLeader,
    });
  }

  // Join Requests
  if (pathname.match(/^\/api\/projects\/([^/]+)\/join-requests$/)) {
    const projId = pathname.split("/")[3];
    if (!user) return sendJSON(res, { error: "Unauthorized" }, 401);

    if (method === "GET") {
      const proj = db.projects.find((p) => p.id === projId);
      if (!proj || proj.leaderId !== user.id) return sendJSON(res, { error: "Forbidden" }, 403);
      const reqs = db.joinRequests
        .filter((r) => r.projectId === projId && r.status === "PENDING")
        .map((r) => {
          const u = db.users.find((x) => x.id === r.userId);
          return {
            ...r,
            user: u ? { id: u.id, name: u.name, school: u.school, skills: u.skills, bio: u.bio } : null,
          };
        });
      return sendJSON(res, { requests: reqs });
    }

    if (method === "POST") {
      const { message } = await parseBody(req);
      const isAlreadyMember = db.members.some((m) => m.projectId === projId && m.userId === user.id);
      if (isAlreadyMember) return sendJSON(res, { error: "Already a member" }, 400);

      const existing = db.joinRequests.find((r) => r.projectId === projId && r.userId === user.id && r.status === "PENDING");
      if (existing) return sendJSON(res, { error: "Request already pending" }, 400);

      const joinReq = {
        id: "jr_" + crypto.randomUUID().slice(0, 8),
        projectId: projId,
        userId: user.id,
        message: message || "",
        status: "PENDING",
        createdAt: new Date().toISOString(),
      };
      db.joinRequests.push(joinReq);
      saveDB();
      broadcastEvent("JOIN_REQUEST", joinReq);
      return sendJSON(res, { joinRequest: joinReq }, 201);
    }
  }

  // Join Request Response (PATCH)
  if (pathname.match(/^\/api\/projects\/([^/]+)\/join-requests\/([^/]+)$/) && method === "PATCH") {
    const [, , , projId, reqId] = pathname.split("/");
    if (!user) return sendJSON(res, { error: "Unauthorized" }, 401);
    const proj = db.projects.find((p) => p.id === projId);
    if (!proj || proj.leaderId !== user.id) return sendJSON(res, { error: "Forbidden" }, 403);

    const joinReq = db.joinRequests.find((r) => r.id === reqId);
    if (!joinReq) return sendJSON(res, { error: "Not found" }, 404);

    const { action } = await parseBody(req);
    joinReq.status = action;

    if (action === "APPROVED") {
      db.members.push({
        id: "m_" + crypto.randomUUID().slice(0, 8),
        projectId: projId,
        userId: joinReq.userId,
        role: "MEMBER",
        joinedAt: new Date().toISOString(),
      });
    }
    saveDB();
    broadcastEvent("JOIN_REQUEST_UPDATED", { projId, reqId, action });
    return sendJSON(res, { success: true, status: action });
  }

  // Tasks (GET & POST)
  if (pathname.match(/^\/api\/projects\/([^/]+)\/tasks$/)) {
    const projId = pathname.split("/")[3];
    if (!user) return sendJSON(res, { error: "Unauthorized" }, 401);

    if (method === "GET") {
      const tasks = db.tasks.filter((t) => t.projectId === projId).map((t) => {
        const assignee = db.users.find((u) => u.id === t.assigneeId);
        const creator = db.users.find((u) => u.id === t.creatorId);
        return {
          ...t,
          assignee: assignee ? { id: assignee.id, name: assignee.name } : null,
          creator: creator ? { id: creator.id, name: creator.name } : null,
        };
      });
      return sendJSON(res, { tasks });
    }

    if (method === "POST") {
      const { title, description, assigneeId, dueDate } = await parseBody(req);
      if (!title) return sendJSON(res, { error: "Title required" }, 400);

      const newTask = {
        id: "t_" + crypto.randomUUID().slice(0, 8),
        projectId: projId,
        title,
        description: description || "",
        status: "TODO",
        assigneeId: assigneeId || null,
        creatorId: user.id,
        dueDate: dueDate || null,
        createdAt: new Date().toISOString(),
      };
      db.tasks.push(newTask);
      saveDB();
      broadcastEvent("TASK_CREATED", newTask);
      return sendJSON(res, { task: newTask }, 201);
    }
  }

  // Task Status Update (PATCH)
  if (pathname.match(/^\/api\/projects\/([^/]+)\/tasks\/([^/]+)$/) && method === "PATCH") {
    const [, , , projId, taskId] = pathname.split("/");
    if (!user) return sendJSON(res, { error: "Unauthorized" }, 401);
    const task = db.tasks.find((t) => t.id === taskId && t.projectId === projId);
    if (!task) return sendJSON(res, { error: "Not found" }, 404);

    const { status, title, description, assigneeId } = await parseBody(req);
    if (status) task.status = status;
    if (title) task.title = title;
    if (description !== undefined) task.description = description;
    if (assigneeId !== undefined) task.assigneeId = assigneeId;
    saveDB();
    broadcastEvent("TASK_UPDATED", task);
    return sendJSON(res, { task });
  }

  // Polls (GET & POST)
  if (pathname.match(/^\/api\/projects\/([^/]+)\/polls$/)) {
    const projId = pathname.split("/")[3];
    if (!user) return sendJSON(res, { error: "Unauthorized" }, 401);

    if (method === "GET") {
      const polls = db.polls.filter((p) => p.projectId === projId).map((poll) => {
        const creator = db.users.find((u) => u.id === poll.createdById);
        const votes = db.pollVotes.filter((v) => v.pollId === poll.id);
        const voteCounts = poll.options.map((_, i) =>
          votes.filter((v) => v.optionIndexes.includes(i)).length
        );
        const userVote = votes.find((v) => v.userId === user.id)?.optionIndexes || [];
        return {
          ...poll,
          createdBy: creator ? { id: creator.id, name: creator.name } : null,
          voteCounts,
          userVote,
          totalVoters: votes.length,
        };
      });
      return sendJSON(res, { polls });
    }

    if (method === "POST") {
      const { question, options, isMultiChoice } = await parseBody(req);
      if (!question || !options || options.length < 2) {
        return sendJSON(res, { error: "Question & at least 2 options required" }, 400);
      }
      const newPoll = {
        id: "poll_" + crypto.randomUUID().slice(0, 8),
        projectId: projId,
        createdById: user.id,
        question,
        options,
        isMultiChoice: !!isMultiChoice,
        createdAt: new Date().toISOString(),
      };
      db.polls.unshift(newPoll);
      saveDB();
      broadcastEvent("POLL_CREATED", newPoll);
      return sendJSON(res, { poll: newPoll }, 201);
    }
  }

  // Poll Vote (POST)
  if (pathname.match(/^\/api\/projects\/([^/]+)\/polls\/([^/]+)\/vote$/) && method === "POST") {
    const [, , , projId, pollId] = pathname.split("/");
    if (!user) return sendJSON(res, { error: "Unauthorized" }, 401);
    const { optionIndexes } = await parseBody(req);

    const existingIndex = db.pollVotes.findIndex((v) => v.pollId === pollId && v.userId === user.id);
    if (existingIndex >= 0) {
      db.pollVotes[existingIndex].optionIndexes = optionIndexes;
    } else {
      db.pollVotes.push({
        id: "pv_" + crypto.randomUUID().slice(0, 8),
        pollId,
        userId: user.id,
        optionIndexes,
      });
    }
    saveDB();
    broadcastEvent("POLL_VOTED", { pollId, userId: user.id, optionIndexes });
    return sendJSON(res, { success: true });
  }

  // Messages (Project & Global)
  if (pathname.match(/^\/api\/projects\/([^/]+)\/messages$/) || pathname === "/api/global-chat") {
    const isGlobal = pathname === "/api/global-chat";
    const projId = isGlobal ? null : pathname.split("/")[3];

    if (method === "GET") {
      const msgs = db.messages
        .filter((m) => (isGlobal ? m.room === "GLOBAL" : m.room === "PROJECT" && m.projectId === projId))
        .map((m) => {
          const sender = db.users.find((u) => u.id === m.senderId);
          return {
            ...m,
            sender: sender ? { id: sender.id, name: sender.name } : { id: "unknown", name: "User" },
          };
        });
      return sendJSON(res, { messages: msgs.slice(-50) });
    }

    if (method === "POST") {
      if (!user) return sendJSON(res, { error: "Unauthorized" }, 401);
      const { content } = await parseBody(req);
      if (!content || !content.trim()) return sendJSON(res, { error: "Content required" }, 400);

      let sanitized = content.replace(/\b(spam|abuse)\b/gi, "****");

      const newMsg = {
        id: "msg_" + crypto.randomUUID().slice(0, 8),
        room: isGlobal ? "GLOBAL" : "PROJECT",
        projectId: projId,
        senderId: user.id,
        content: sanitized,
        createdAt: new Date().toISOString(),
      };
      db.messages.push(newMsg);
      saveDB();

      const enriched = { ...newMsg, sender: { id: user.id, name: user.name } };
      broadcastEvent(isGlobal ? "GLOBAL_MESSAGE" : "PROJECT_MESSAGE", enriched);
      return sendJSON(res, { message: enriched }, 201);
    }
  }

  // Media (GET & POST)
  if (pathname.match(/^\/api\/projects\/([^/]+)\/media$/)) {
    const projId = pathname.split("/")[3];
    if (!user) return sendJSON(res, { error: "Unauthorized" }, 401);

    if (method === "GET") {
      const items = db.media.filter((m) => m.projectId === projId).map((m) => {
        const uploader = db.users.find((u) => u.id === m.uploaderId);
        return {
          ...m,
          uploader: uploader ? { id: uploader.id, name: uploader.name } : null,
        };
      });
      return sendJSON(res, { items });
    }

    if (method === "POST") {
      const { name, url: mediaUrl, type } = await parseBody(req);
      if (!mediaUrl) return sendJSON(res, { error: "URL required" }, 400);

      const newItem = {
        id: "med_" + crypto.randomUUID().slice(0, 8),
        projectId: projId,
        uploaderId: user.id,
        name: name || mediaUrl,
        url: mediaUrl,
        type: type || "LINK",
        createdAt: new Date().toISOString(),
      };
      db.media.unshift(newItem);
      saveDB();
      broadcastEvent("MEDIA_ADDED", newItem);
      return sendJSON(res, { item: newItem }, 201);
    }
  }

  // Profile (GET & PATCH)
  if (pathname.startsWith("/api/users/")) {
    const targetId = pathname.split("/")[3];
    const target = db.users.find((u) => u.id === targetId);
    if (!target) return sendJSON(res, { error: "User not found" }, 404);

    if (method === "GET") {
      const userProjects = db.members
        .filter((m) => m.userId === targetId)
        .map((m) => {
          const p = db.projects.find((x) => x.id === m.projectId);
          return p ? { id: p.id, name: p.name, description: p.description, tags: p.tags, visibility: p.visibility } : null;
        })
        .filter(Boolean);

      const { salt, passwordHash, ...safe } = target;
      return sendJSON(res, { user: { ...safe, projects: userProjects } });
    }

    if (method === "PATCH") {
      if (!user || user.id !== targetId) return sendJSON(res, { error: "Forbidden" }, 403);
      const { name, bio, githubUrl, school, skills } = await parseBody(req);
      if (name) target.name = name;
      if (bio !== undefined) target.bio = bio;
      if (githubUrl !== undefined) target.githubUrl = githubUrl;
      if (school !== undefined) target.school = school;
      if (skills !== undefined) target.skills = skills;
      saveDB();
      const { salt, passwordHash, ...safe } = target;
      return sendJSON(res, { user: safe });
    }
  }

  // Serve Static Assets from /public or /images
  if (pathname.startsWith("/public/") || pathname.startsWith("/images/")) {
    const relPath = pathname.startsWith("/public/") ? pathname.replace(/^\/public\//, "") : pathname.replace(/^\//, "");
    const filePath = path.join(__dirname, "public", relPath);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const mimeTypes = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".svg": "image/svg+xml",
        ".webp": "image/webp",
        ".gif": "image/gif",
        ".ico": "image/x-icon",
        ".css": "text/css",
        ".js": "application/javascript"
      };
      res.writeHead(200, { "Content-Type": mimeTypes[ext] || "application/octet-stream" });
      return res.end(fs.readFileSync(filePath));
    }
  }

  // Serve Clean Standalone HTML App
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
  });
  const indexPath = path.join(__dirname, "index.html");
  if (fs.existsSync(indexPath)) {
    res.end(fs.readFileSync(indexPath, "utf-8"));
  } else {
    res.end(getAppHTML());
  }
});


// --- MODERN VANILLA CSS SPA (NO EXTERNAL SCRIPTS / ZERO PHISHING TRIGGERS) ---
function getAppHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pronnect — Local Project Collaboration</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background-color: #030712; color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; min-height: 100vh; display: flex; flex-direction: column; }
    
    /* Layout */
    .container { max-width: 1200px; margin: 0 auto; width: 100%; padding: 24px 16px; flex: 1; }
    nav { background: rgba(17, 24, 39, 0.85); backdrop-filter: blur(12px); border-bottom: 1px solid #1f2937; position: sticky; top: 0; z-index: 50; padding: 12px 24px; }
    .nav-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }
    .nav-links { display: flex; gap: 8px; align-items: center; }
    
    /* Cards & Components */
    .glass-card { background: rgba(31, 41, 55, 0.5); border: 1px solid #374151; border-radius: 12px; padding: 20px; }
    .grid { display: grid; gap: 16px; }
    .grid-3 { grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); }
    .grid-kanban { grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
    .flex { display: flex; }
    .flex-col { flex-direction: column; }
    .items-center { align-items: center; }
    .justify-between { justify-content: space-between; }
    .gap-2 { gap: 8px; }
    .gap-3 { gap: 12px; }
    .gap-4 { gap: 16px; }
    
    /* Typography & Colors */
    .gradient-text { background: linear-gradient(135deg, #6366f1, #a855f7, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 800; }
    .text-sm { font-size: 0.875rem; }
    .text-xs { font-size: 0.75rem; }
    .text-muted { color: #9ca3af; }
    .badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 500; background: #1f2937; border: 1px solid #374151; color: #d1d5db; }
    .badge-indigo { background: rgba(99, 102, 241, 0.15); border-color: rgba(99, 102, 241, 0.3); color: #a5b4fc; }
    .badge-green { background: rgba(34, 197, 94, 0.15); border-color: rgba(34, 197, 94, 0.3); color: #86efac; }
    .badge-yellow { background: rgba(234, 179, 8, 0.15); border-color: rgba(234, 179, 8, 0.3); color: #fde047; }
    
    /* Form controls */
    input, textarea, select { width: 100%; padding: 10px 14px; background: #111827; border: 1px solid #374151; border-radius: 8px; color: #f9fafb; font-size: 0.875rem; outline: none; transition: border-color 0.2s; }
    input:focus, textarea:focus, select:focus { border-color: #6366f1; }
    button { cursor: pointer; border: none; border-radius: 8px; font-weight: 500; font-size: 0.875rem; transition: all 0.2s; }
    .btn { padding: 8px 16px; }
    .btn-primary { background: #6366f1; color: white; }
    .btn-primary:hover { background: #4f46e5; }
    .btn-secondary { background: #1f2937; color: #e5e7eb; border: 1px solid #374151; }
    .btn-secondary:hover { background: #374151; }
    .btn-sm { padding: 6px 12px; font-size: 0.75rem; }
    
    /* Scrollable chat */
    .chat-box { height: 460px; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 10px; background: #0b0f19; border-radius: 8px; }
    .msg-bubble { padding: 8px 14px; border-radius: 16px; max-width: 80%; font-size: 0.875rem; }
    .msg-me { align-self: flex-end; background: #6366f1; color: white; border-bottom-right-radius: 2px; }
    .msg-other { align-self: flex-start; background: #1f2937; color: #f3f4f6; border-bottom-left-radius: 2px; }
    
    /* Progress bar */
    .progress-track { width: 100%; height: 10px; background: #1f2937; border-radius: 9999px; overflow: hidden; }
    .progress-fill { height: 100%; background: linear-gradient(90deg, #6366f1, #22c55e); transition: width 0.4s; }
    
    /* Toast */
    #toast-root { position: fixed; bottom: 20px; right: 20px; z-index: 100; display: flex; flex-direction: column; gap: 8px; pointer-events: none; }
    .toast { padding: 12px 18px; border-radius: 8px; font-size: 0.875rem; background: #111827; border: 1px solid #6366f1; color: white; box-shadow: 0 10px 25px rgba(0,0,0,0.5); pointer-events: auto; }
    .toast-err { border-color: #ef4444; background: #450a0a; }
  </style>
</head>
<body>
  <!-- NAV -->
  <nav>
    <div class="nav-inner">
      <div style="display:flex; align-items:center; gap:20px;">
        <div onclick="navigate('explore')" style="display:flex; align-items:center; gap:8px; cursor:pointer;">
          <div style="width:32px; height:32px; border-radius:8px; background:#6366f1; display:flex; align-items:center; justify-content:center; font-weight:bold; color:white;">P</div>
          <span class="gradient-text" style="font-size:1.25rem;">Pronnect</span>
        </div>
        <div class="nav-links">
          <button class="btn btn-secondary" onclick="navigate('explore')">Explore</button>
          <button class="btn btn-secondary" onclick="navigate('global-chat')">Global Chat</button>
          <button class="btn btn-secondary" onclick="navigate('new-project')">+ New Project</button>
        </div>
      </div>
      <div id="nav-auth" style="display:flex; align-items:center; gap:12px;"></div>
    </div>
  </nav>

  <!-- CONTENT -->
  <div class="container" id="app-root"></div>
  <div id="toast-root"></div>

  <script>
    let currentUser = null;
    let currentView = 'explore';
    let activeProjectId = null;
    let activeProjectTab = 'chat';
    let projectsCache = [];
    let domainTags = ["AI/ML", "Web Dev", "Mobile", "Embedded Systems", "Robotics", "IoT", "Cybersecurity", "Data Science", "Research"];

    function showToast(msg, isError = false) {
      const root = document.getElementById('toast-root');
      const toast = document.createElement('div');
      toast.className = 'toast ' + (isError ? 'toast-err' : '');
      toast.innerHTML = (isError ? '⚠️ ' : '✅ ') + msg;
      root.appendChild(toast);
      setTimeout(() => { toast.remove(); }, 3500);
    }

    async function init() {
      setupRealtimeSSE();
      await checkAuth();
      navigate('explore');
    }

    function setupRealtimeSSE() {
      const evtSource = new EventSource('/api/events');
      evtSource.onmessage = (e) => {
        try {
          const { type } = JSON.parse(e.data);
          if (type === 'GLOBAL_MESSAGE' && currentView === 'global-chat') loadGlobalChat();
          if (type === 'PROJECT_MESSAGE' && currentView === 'project' && activeProjectTab === 'chat') loadProjectChat(activeProjectId);
          if (type === 'TASK_CREATED' || type === 'TASK_UPDATED') {
            if (currentView === 'project' && activeProjectTab === 'tasks') loadProjectTasks(activeProjectId);
            if (currentView === 'project' && activeProjectTab === 'progress') loadProjectProgress(activeProjectId);
          }
          if (type === 'POLL_CREATED' || type === 'POLL_VOTED') {
            if (currentView === 'project' && activeProjectTab === 'polls') loadProjectPolls(activeProjectId);
          }
          if (type === 'JOIN_REQUEST' || type === 'JOIN_REQUEST_UPDATED') {
            if (currentView === 'project') renderProjectView(activeProjectId);
          }
        } catch (err) {}
      };
    }

    async function checkAuth() {
      try {
        const res = await fetch('/api/auth/me');
        const data = await res.json();
        currentUser = data.user;
        renderNavAuth();
      } catch (e) {
        currentUser = null;
        renderNavAuth();
      }
    }

    function renderNavAuth() {
      const container = document.getElementById('nav-auth');
      if (currentUser) {
        container.innerHTML = \`
          <button onclick="navigate('profile', '\${currentUser.id}')" class="btn btn-secondary" style="display:flex; align-items:center; gap:6px;">
            <div style="width:20px; height:20px; border-radius:50%; background:#6366f1; color:white; font-size:10px; display:flex; align-items:center; justify-content:center; font-weight:bold;">\${currentUser.name.slice(0, 1).toUpperCase()}</div>
            <span>\${escapeHtml(currentUser.name)}</span>
          </button>
          <button onclick="logout()" class="btn btn-secondary btn-sm" style="color:#ef4444;">Sign Out</button>
        \`;
      } else {
        container.innerHTML = \`
          <button onclick="navigate('login')" class="btn btn-secondary">Sign In</button>
          <button onclick="navigate('register')" class="btn btn-primary">Get Started</button>
        \`;
      }
    }

    async function logout() {
      await fetch('/api/auth/logout', { method: 'POST' });
      currentUser = null;
      renderNavAuth();
      showToast('Logged out');
      navigate('explore');
    }

    function navigate(view, param = null) {
      currentView = view;
      if (view === 'explore') renderExploreView();
      else if (view === 'login') renderLoginView();
      else if (view === 'register') renderRegisterView();
      else if (view === 'new-project') renderNewProjectView();
      else if (view === 'project') renderProjectView(param);
      else if (view === 'global-chat') renderGlobalChatView();
      else if (view === 'profile') renderProfileView(param || (currentUser ? currentUser.id : null));
    }

    // --- EXPLORE ---
    async function renderExploreView() {
      const root = document.getElementById('app-root');
      root.innerHTML = \`
        <div style="display:flex; flex-direction:column; gap:20px;">
          <div class="flex justify-between items-center">
            <div>
              <h1 style="font-size:1.75rem; font-weight:bold;">Explore Projects</h1>
              <p class="text-muted text-sm">Find teammates and open collaboration projects</p>
            </div>
            <button onclick="navigate('new-project')" class="btn btn-primary">+ Create Project</button>
          </div>

          <div class="glass-card" style="display:flex; flex-direction:column; gap:12px;">
            <div style="display:flex; gap:12px; flex-wrap:wrap;">
              <input id="search-input" oninput="debounceSearch()" placeholder="Search projects..." style="flex:1; min-width:200px;" />
              <input id="school-input" oninput="debounceSearch()" placeholder="Filter by school/institution..." style="flex:1; min-width:200px;" />
            </div>
            <div style="display:flex; gap:6px; flex-wrap:wrap;" id="tag-filters">
              <button onclick="selectTag('')" id="tag-btn-all" class="badge badge-indigo" style="cursor:pointer; padding:6px 12px;">All Tags</button>
              \${domainTags.map(t => \`<button onclick="selectTag('\${t}')" id="tag-btn-\${t.replace(/[^a-zA-Z]/g, '')}" class="badge" style="cursor:pointer; padding:6px 12px;">\${t}</button>\`).join('')}
            </div>
          </div>

          <div id="projects-grid" class="grid grid-3">Loading projects...</div>
        </div>
      \`;
      loadProjects();
    }

    let activeTag = '';
    let searchDebounceTimer = null;
    function debounceSearch() {
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(loadProjects, 300);
    }

    function selectTag(tag) {
      activeTag = tag;
      document.querySelectorAll('#tag-filters button').forEach(b => { b.className = 'badge'; });
      const sel = tag ? document.getElementById('tag-btn-' + tag.replace(/[^a-zA-Z]/g, '')) : document.getElementById('tag-btn-all');
      if (sel) sel.className = 'badge badge-indigo';
      loadProjects();
    }

    async function loadProjects() {
      const search = document.getElementById('search-input')?.value || '';
      const school = document.getElementById('school-input')?.value || '';
      const params = new URLSearchParams();
      if (search) params.set('search', search);
      if (school) params.set('school', school);
      if (activeTag) params.set('tag', activeTag);

      const res = await fetch('/api/projects?' + params.toString());
      const data = await res.json();
      projectsCache = data.projects || [];
      const grid = document.getElementById('projects-grid');
      if (!grid) return;

      if (projectsCache.length === 0) {
        grid.innerHTML = '<div style="grid-column:1/-1; text-align:center; padding:40px; color:#6b7280;">No projects found.</div>';
        return;
      }

      grid.innerHTML = projectsCache.map(p => \`
        <div class="glass-card flex flex-col justify-between" style="cursor:pointer;" onclick="navigate('project', '\${p.id}')">
          <div>
            <div class="flex justify-between items-center" style="margin-bottom:8px;">
              <h3 style="font-size:1.1rem; font-weight:600; color:#f3f4f6;">\${escapeHtml(p.name)}</h3>
              <span class="badge">\${p._count.members} member\${p._count.members !== 1 ? 's' : ''}</span>
            </div>
            <p class="text-muted text-sm" style="margin-bottom:12px;">\${escapeHtml(p.description)}</p>
            <div style="display:flex; flex-wrap:wrap; gap:4px; margin-bottom:16px;">
              \${p.tags.map(t => \`<span class="badge badge-indigo">\${t}</span>\`).join('')}
            </div>
          </div>
          <div class="flex justify-between items-center" style="padding-top:10px; border-top:1px solid #1f2937;">
            <div style="font-size:0.75rem; color:#9ca3af;">
              <div>Led by <strong>\${p.leader ? escapeHtml(p.leader.name) : 'Anonymous'}</strong></div>
              \${p.leader && p.leader.school ? \`<div>🎓 \${escapeHtml(p.leader.school)}</div>\` : ''}
            </div>
            <button class="btn btn-secondary btn-sm">View &rarr;</button>
          </div>
        </div>
      \`).join('');
    }

    // --- PROJECT WORKSPACE ---
    async function renderProjectView(projectId) {
      activeProjectId = projectId;
      const root = document.getElementById('app-root');
      root.innerHTML = '<div style="text-align:center; padding:60px; color:#9ca3af;">Loading workspace...</div>';

      const res = await fetch('/api/projects/' + projectId);
      if (!res.ok) {
        root.innerHTML = '<div style="text-align:center; padding:60px; color:#ef4444;">Project not found.</div>';
        return;
      }
      const { project, isMember, isLeader } = await res.json();

      root.innerHTML = \`
        <div style="display:flex; flex-direction:column; gap:20px;">
          <div class="glass-card flex justify-between items-center" style="flex-wrap:wrap; gap:16px;">
            <div>
              <div style="display:flex; align-items:center; gap:8px;">
                <h1 style="font-size:1.5rem; font-weight:bold;">\${escapeHtml(project.name)}</h1>
                <span class="badge \${project.visibility === 'PUBLIC' ? 'badge-green' : 'badge-yellow'}">\${project.visibility}</span>
              </div>
              <p class="text-muted text-sm" style="margin-top:6px;">\${escapeHtml(project.description)}</p>
              <div style="display:flex; gap:6px; margin-top:10px;">
                \${project.tags.map(t => \`<span class="badge badge-indigo">\${t}</span>\`).join('')}
              </div>
            </div>
            <div>
              \${!isMember && currentUser ? \`<button onclick="requestToJoin('\${project.id}')" class="btn btn-primary">Request to Join</button>\` : ''}
              \${!currentUser ? \`<button onclick="navigate('login')" class="btn btn-secondary">Sign in to Join</button>\` : ''}
            </div>
          </div>

          \${!isMember ? \`
            <div class="glass-card" style="text-align:center; padding:48px; color:#9ca3af;">
              <div style="font-size:2rem; margin-bottom:8px;">🔒</div>
              <h3>Members-Only Project Workspace</h3>
              <p class="text-muted text-sm" style="margin-top:4px;">Join this project to access team chat, tasks, polls, and media.</p>
            </div>
          \` : \`
            <div style="display:flex; gap:8px; border-bottom:1px solid #1f2937; padding-bottom:8px; overflow-x:auto;">
              <button onclick="switchProjectTab('chat')" id="ptab-chat" class="btn btn-primary btn-sm">💬 Team Chat</button>
              <button onclick="switchProjectTab('tasks')" id="ptab-tasks" class="btn btn-secondary btn-sm">📋 Tasks</button>
              <button onclick="switchProjectTab('polls')" id="ptab-polls" class="btn btn-secondary btn-sm">📊 Polls</button>
              <button onclick="switchProjectTab('media')" id="ptab-media" class="btn btn-secondary btn-sm">📁 Media & Links</button>
              <button onclick="switchProjectTab('progress')" id="ptab-progress" class="btn btn-secondary btn-sm">📈 Progress</button>
              \${isLeader ? \`<button onclick="switchProjectTab('requests')" id="ptab-requests" class="btn btn-secondary btn-sm">👥 Join Requests</button>\` : ''}
            </div>
            <div id="project-tab-content"></div>
          \`}
        </div>
      \`;

      if (isMember) switchProjectTab(activeProjectTab || 'chat');
    }

    async function requestToJoin(projId) {
      const res = await fetch('/api/projects/' + projId + '/join-requests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: "Requesting to join!" })
      });
      if (res.ok) {
        showToast("Join request sent!");
        renderProjectView(projId);
      } else {
        const d = await res.json();
        showToast(d.error || "Failed", true);
      }
    }

    function switchProjectTab(tab) {
      activeProjectTab = tab;
      document.querySelectorAll('[id^="ptab-"]').forEach(b => { b.className = 'btn btn-secondary btn-sm'; });
      const active = document.getElementById('ptab-' + tab);
      if (active) active.className = 'btn btn-primary btn-sm';

      if (tab === 'chat') loadProjectChat(activeProjectId);
      else if (tab === 'tasks') loadProjectTasks(activeProjectId);
      else if (tab === 'polls') loadProjectPolls(activeProjectId);
      else if (tab === 'media') loadProjectMedia(activeProjectId);
      else if (tab === 'progress') loadProjectProgress(activeProjectId);
      else if (tab === 'requests') loadProjectRequests(activeProjectId);
    }

    async function loadProjectChat(projId) {
      const container = document.getElementById('project-tab-content');
      container.innerHTML = \`
        <div class="glass-card" style="display:flex; flex-direction:column; gap:12px;">
          <div id="chat-messages" class="chat-box">Loading chat...</div>
          <form onsubmit="sendProjectMessage(event, '\${projId}')" style="display:flex; gap:8px;">
            <input id="proj-msg-input" placeholder="Type a message to the team..." style="flex:1;" />
            <button type="submit" class="btn btn-primary">Send</button>
          </form>
        </div>
      \`;
      const res = await fetch('/api/projects/' + projId + '/messages');
      const data = await res.json();
      renderChatMessages('chat-messages', data.messages || []);
    }

    function renderChatMessages(elementId, msgs) {
      const box = document.getElementById(elementId);
      if (!box) return;
      if (msgs.length === 0) {
        box.innerHTML = '<div style="text-align:center; color:#6b7280; margin:auto;">No messages yet. Say hello! 👋</div>';
        return;
      }
      box.innerHTML = msgs.map(m => {
        const isMe = currentUser && m.senderId === currentUser.id;
        return \`
          <div style="display:flex; flex-direction:column; align-items:\${isMe ? 'flex-end' : 'flex-start'};">
            <div class="text-muted text-xs" style="margin-bottom:2px;">\${escapeHtml(m.sender.name)}</div>
            <div class="msg-bubble \${isMe ? 'msg-me' : 'msg-other'}">\${escapeHtml(m.content)}</div>
          </div>
        \`;
      }).join('');
      box.scrollTop = box.scrollHeight;
    }

    async function sendProjectMessage(e, projId) {
      e.preventDefault();
      const input = document.getElementById('proj-msg-input');
      const content = input.value.trim();
      if (!content) return;
      input.value = '';
      await fetch('/api/projects/' + projId + '/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });
      loadProjectChat(projId);
    }

    // --- TASKS ---
    async function loadProjectTasks(projId) {
      const container = document.getElementById('project-tab-content');
      container.innerHTML = \`
        <div style="display:flex; flex-direction:column; gap:16px;">
          <div class="flex justify-between items-center">
            <h3 style="font-weight:600;">Project Tasks</h3>
            <button onclick="showCreateTaskModal('\${projId}')" class="btn btn-primary btn-sm">+ Add Task</button>
          </div>
          <div id="tasks-board" class="grid grid-kanban">Loading tasks...</div>
        </div>
      \`;
      const res = await fetch('/api/projects/' + projId + '/tasks');
      const { tasks = [] } = await res.json();

      const todo = tasks.filter(t => t.status === 'TODO');
      const inProgress = tasks.filter(t => t.status === 'IN_PROGRESS');
      const done = tasks.filter(t => t.status === 'DONE');

      document.getElementById('tasks-board').innerHTML = \`
        \${renderTaskCol('To Do', todo, 'TODO', projId)}
        \${renderTaskCol('In Progress', inProgress, 'IN_PROGRESS', projId)}
        \${renderTaskCol('Done', done, 'DONE', projId)}
      \`;
    }

    function renderTaskCol(title, list, status, projId) {
      return \`
        <div class="glass-card" style="display:flex; flex-direction:column; gap:10px;">
          <div class="flex justify-between items-center text-xs" style="font-weight:bold; color:#9ca3af; text-transform:uppercase;">
            <span>\${title}</span>
            <span class="badge">\${list.length}</span>
          </div>
          <div style="display:flex; flex-direction:column; gap:8px;">
            \${list.length === 0 ? '<div class="text-muted text-xs" style="text-align:center; padding:12px;">No tasks</div>' : ''}
            \${list.map(t => \`
              <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:12px; display:flex; flex-direction:column; gap:6px;">
                <div style="font-size:0.875rem; font-weight:500;">\${escapeHtml(t.title)}</div>
                \${t.description ? \`<div class="text-muted text-xs">\${escapeHtml(t.description)}</div>\` : ''}
                <div class="flex justify-between items-center text-xs" style="margin-top:4px;">
                  <span class="text-muted">\${t.assignee ? '👤 ' + escapeHtml(t.assignee.name) : 'Unassigned'}</span>
                  <select onchange="updateTaskStatus('\${projId}', '\${t.id}', this.value)" style="width:auto; padding:2px 6px; font-size:10px;">
                    <option value="TODO" \${t.status === 'TODO' ? 'selected' : ''}>To Do</option>
                    <option value="IN_PROGRESS" \${t.status === 'IN_PROGRESS' ? 'selected' : ''}>In Progress</option>
                    <option value="DONE" \${t.status === 'DONE' ? 'selected' : ''}>Done</option>
                  </select>
                </div>
              </div>
            \`).join('')}
          </div>
        </div>
      \`;
    }

    async function updateTaskStatus(projId, taskId, status) {
      await fetch('/api/projects/' + projId + '/tasks/' + taskId, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      loadProjectTasks(projId);
    }

    function showCreateTaskModal(projId) {
      const title = prompt("Task title:");
      if (!title) return;
      const description = prompt("Task description (optional):") || "";
      fetch('/api/projects/' + projId + '/tasks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, description })
      }).then(() => loadProjectTasks(projId));
    }

    // --- POLLS ---
    async function loadProjectPolls(projId) {
      const container = document.getElementById('project-tab-content');
      container.innerHTML = \`
        <div style="display:flex; flex-direction:column; gap:16px;">
          <div class="flex justify-between items-center">
            <h3 style="font-weight:600;">Team Polls</h3>
            <button onclick="showCreatePollModal('\${projId}')" class="btn btn-primary btn-sm">+ Create Poll</button>
          </div>
          <div id="polls-list" style="display:flex; flex-direction:column; gap:12px;">Loading polls...</div>
        </div>
      \`;
      const res = await fetch('/api/projects/' + projId + '/polls');
      const { polls = [] } = await res.json();
      const box = document.getElementById('polls-list');
      if (polls.length === 0) {
        box.innerHTML = '<div class="glass-card" style="text-align:center; padding:30px; color:#6b7280;">No polls created yet.</div>';
        return;
      }
      box.innerHTML = polls.map(p => {
        const totalVotes = p.voteCounts.reduce((a, b) => a + b, 0);
        return \`
          <div class="glass-card" style="display:flex; flex-direction:column; gap:12px;">
            <div style="font-size:1rem; font-weight:600;">\${escapeHtml(p.question)}</div>
            <div class="text-muted text-xs">\${p.totalVoters} voter\${p.totalVoters !== 1 ? 's' : ''}</div>
            <div style="display:flex; flex-direction:column; gap:8px;">
              \${p.options.map((opt, idx) => {
                const count = p.voteCounts[idx] || 0;
                const pct = totalVotes > 0 ? Math.round((count / totalVotes) * 100) : 0;
                const hasVoted = p.userVote.includes(idx);
                return \`
                  <button onclick="votePoll('\${projId}', '\${p.id}', \${idx})" class="btn btn-secondary flex justify-between items-center" style="text-align:left; padding:10px 14px; position:relative; overflow:hidden;">
                    <div style="position:absolute; top:0; left:0; bottom:0; width:\${pct}%; background:rgba(99, 102, 241, 0.2);"></div>
                    <span style="position:relative; z-index:2;">\${escapeHtml(opt)} \${hasVoted ? '✓' : ''}</span>
                    <span class="text-muted text-xs" style="position:relative; z-index:2;">\${count} votes (\${pct}%)</span>
                  </button>
                \`;
              }).join('')}
            </div>
          </div>
        \`;
      }).join('');
    }

    async function votePoll(projId, pollId, optionIdx) {
      await fetch('/api/projects/' + projId + '/polls/' + pollId + '/vote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ optionIndexes: [optionIdx] })
      });
      loadProjectPolls(projId);
    }

    function showCreatePollModal(projId) {
      const question = prompt("Poll question:");
      if (!question) return;
      const opt1 = prompt("Option 1:");
      const opt2 = prompt("Option 2:");
      if (!opt1 || !opt2) return;
      fetch('/api/projects/' + projId + '/polls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, options: [opt1, opt2] })
      }).then(() => loadProjectPolls(projId));
    }

    // --- MEDIA ---
    async function loadProjectMedia(projId) {
      const container = document.getElementById('project-tab-content');
      container.innerHTML = \`
        <div style="display:flex; flex-direction:column; gap:16px;">
          <div class="flex justify-between items-center">
            <h3 style="font-weight:600;">Media & Shared Resources</h3>
            <button onclick="showAddMediaModal('\${projId}')" class="btn btn-primary btn-sm">+ Add Resource</button>
          </div>
          <div id="media-grid" class="grid grid-3">Loading media...</div>
        </div>
      \`;
      const res = await fetch('/api/projects/' + projId + '/media');
      const { items = [] } = await res.json();
      const grid = document.getElementById('media-grid');
      if (items.length === 0) {
        grid.innerHTML = '<div style="grid-column:1/-1; text-align:center; padding:30px; color:#6b7280;">No resources shared yet.</div>';
        return;
      }
      grid.innerHTML = items.map(m => \`
        <a href="\${escapeHtml(m.url)}" target="_blank" class="glass-card" style="text-decoration:none; color:inherit; display:flex; gap:12px; align-items:flex-start;">
          <div style="font-size:1.5rem;">🔗</div>
          <div style="overflow:hidden;">
            <div style="font-weight:500; font-size:0.875rem; color:#f3f4f6;">\${escapeHtml(m.name)}</div>
            <div class="text-muted text-xs" style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">\${escapeHtml(m.url)}</div>
          </div>
        </a>
      \`).join('');
    }

    function showAddMediaModal(projId) {
      const name = prompt("Resource name:");
      const url = prompt("Resource URL (https://...):");
      if (!url) return;
      fetch('/api/projects/' + projId + '/media', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name || url, url })
      }).then(() => loadProjectMedia(projId));
    }

    // --- PROGRESS ---
    async function loadProjectProgress(projId) {
      const container = document.getElementById('project-tab-content');
      const res = await fetch('/api/projects/' + projId + '/tasks');
      const { tasks = [] } = await res.json();

      const total = tasks.length;
      const done = tasks.filter(t => t.status === 'DONE').length;
      const inProgress = tasks.filter(t => t.status === 'IN_PROGRESS').length;
      const todo = tasks.filter(t => t.status === 'TODO').length;
      const pct = total > 0 ? Math.round((done / total) * 100) : 0;

      container.innerHTML = \`
        <div class="glass-card" style="display:flex; flex-direction:column; gap:20px;">
          <h3 style="font-weight:600;">Milestone & Progress Overview</h3>
          <div class="grid grid-3">
            <div class="glass-card" style="text-align:center; background:#111827;">
              <div style="font-size:1.75rem; font-weight:bold;">\${total}</div>
              <div class="text-muted text-xs">Total Tasks</div>
            </div>
            <div class="glass-card" style="text-align:center; background:#111827;">
              <div style="font-size:1.75rem; font-weight:bold; color:#eab308;">\${inProgress}</div>
              <div class="text-muted text-xs">In Progress</div>
            </div>
            <div class="glass-card" style="text-align:center; background:#111827;">
              <div style="font-size:1.75rem; font-weight:bold; color:#22c55e;">\${done}</div>
              <div class="text-muted text-xs">Completed</div>
            </div>
          </div>
          <div style="display:flex; flex-direction:column; gap:8px;">
            <div class="flex justify-between text-xs" style="font-weight:500;">
              <span>Overall Completion</span>
              <span>\${pct}%</span>
            </div>
            <div class="progress-track">
              <div class="progress-fill" style="width:\${pct}%;"></div>
            </div>
          </div>
        </div>
      \`;
    }

    // --- REQUESTS ---
    async function loadProjectRequests(projId) {
      const container = document.getElementById('project-tab-content');
      const res = await fetch('/api/projects/' + projId + '/join-requests');
      const { requests = [] } = await res.json();
      container.innerHTML = \`
        <div class="glass-card" style="display:flex; flex-direction:column; gap:16px;">
          <h3 style="font-weight:600;">Pending Join Requests (\${requests.length})</h3>
          \${requests.length === 0 ? '<div class="text-muted text-sm" style="text-align:center; padding:20px;">No pending join requests</div>' : ''}
          <div style="display:flex; flex-direction:column; gap:10px;">
            \${requests.map(r => \`
              <div class="flex justify-between items-center" style="background:#111827; padding:12px 16px; border-radius:8px; border:1px solid #1f2937;">
                <div>
                  <div style="font-weight:500;">\${escapeHtml(r.user ? r.user.name : 'User')}</div>
                  <div class="text-muted text-xs">\${escapeHtml(r.user ? r.user.school : '')}</div>
                </div>
                <div style="display:flex; gap:8px;">
                  <button onclick="handleJoinRequest('\${projId}', '\${r.id}', 'DENIED')" class="btn btn-secondary btn-sm" style="color:#ef4444;">Deny</button>
                  <button onclick="handleJoinRequest('\${projId}', '\${r.id}', 'APPROVED')" class="btn btn-primary btn-sm" style="background:#16a34a;">Approve</button>
                </div>
              </div>
            \`).join('')}
          </div>
        </div>
      \`;
    }

    async function handleJoinRequest(projId, reqId, action) {
      await fetch('/api/projects/' + projId + '/join-requests/' + reqId, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action })
      });
      showToast(action === 'APPROVED' ? 'Member approved!' : 'Denied');
      loadProjectRequests(projId);
    }

    // --- CREATE PROJECT ---
    function renderNewProjectView() {
      if (!currentUser) { navigate('login'); return; }
      const root = document.getElementById('app-root');
      root.innerHTML = \`
        <div class="glass-card" style="max-width:600px; margin:0 auto; display:flex; flex-direction:column; gap:16px;">
          <h1 style="font-size:1.5rem; font-weight:bold;">Create a New Project</h1>
          <form onsubmit="submitNewProject(event)" style="display:flex; flex-direction:column; gap:14px;">
            <div>
              <label class="text-xs" style="margin-bottom:4px; display:block;">Project Name</label>
              <input id="new-proj-name" required placeholder="e.g. Autonomous Drone Swarm" />
            </div>
            <div>
              <label class="text-xs" style="margin-bottom:4px; display:block;">Description</label>
              <textarea id="new-proj-desc" required rows="3" placeholder="What are you building?"></textarea>
            </div>
            <div>
              <label class="text-xs" style="margin-bottom:4px; display:block;">Visibility</label>
              <select id="new-proj-vis">
                <option value="PUBLIC">Public (Visible to everyone)</option>
                <option value="PRIVATE">Private (Direct link only)</option>
              </select>
            </div>
            <div>
              <label class="text-xs" style="margin-bottom:4px; display:block;">Tags</label>
              <div style="display:flex; flex-wrap:wrap; gap:6px;">
                \${domainTags.map(t => \`<button type="button" onclick="toggleTag('\${t}', this)" class="badge" style="cursor:pointer; padding:6px 10px;">\${t}</button>\`).join('')}
              </div>
            </div>
            <div style="display:flex; gap:8px; margin-top:8px;">
              <button type="button" onclick="navigate('explore')" class="btn btn-secondary">Cancel</button>
              <button type="submit" class="btn btn-primary" style="flex:1;">Create Project</button>
            </div>
          </form>
        </div>
      \`;
    }

    let selectedTags = [];
    function toggleTag(t, btn) {
      if (selectedTags.includes(t)) {
        selectedTags = selectedTags.filter(x => x !== t);
        btn.className = 'badge';
      } else {
        selectedTags.push(t);
        btn.className = 'badge badge-indigo';
      }
    }

    async function submitNewProject(e) {
      e.preventDefault();
      const name = document.getElementById('new-proj-name').value.trim();
      const description = document.getElementById('new-proj-desc').value.trim();
      const visibility = document.getElementById('new-proj-vis').value;
      const res = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, description, visibility, tags: selectedTags })
      });
      const data = await res.json();
      if (res.ok) {
        showToast('Project created!');
        selectedTags = [];
        navigate('project', data.project.id);
      } else {
        showToast(data.error || 'Error', true);
      }
    }

    // --- GLOBAL CHAT ---
    async function renderGlobalChatView() {
      const root = document.getElementById('app-root');
      root.innerHTML = \`
        <div style="max-w:800px; margin:0 auto; display:flex; flex-direction:column; gap:16px;">
          <div class="flex justify-between items-center">
            <div>
              <h1 style="font-size:1.5rem; font-weight:bold;">Global Community Chat</h1>
              <p class="text-muted text-xs">Live platform-wide chat for makers</p>
            </div>
            <span class="badge badge-green">Live SSE</span>
          </div>
          <div class="glass-card" style="display:flex; flex-direction:column; gap:12px;">
            <div id="global-chat-messages" class="chat-box">Loading chat...</div>
            <form onsubmit="sendGlobalMessage(event)" style="display:flex; gap:8px;">
              <input id="global-msg-input" placeholder="\${currentUser ? 'Send a message to the community...' : 'Sign in to participate...'}" \${!currentUser ? 'disabled' : ''} style="flex:1;" />
              <button type="submit" \${!currentUser ? 'disabled' : ''} class="btn btn-primary">Send</button>
            </form>
          </div>
        </div>
      \`;
      loadGlobalChat();
    }

    async function loadGlobalChat() {
      const res = await fetch('/api/global-chat');
      const data = await res.json();
      renderChatMessages('global-chat-messages', data.messages || []);
    }

    async function sendGlobalMessage(e) {
      e.preventDefault();
      if (!currentUser) return;
      const input = document.getElementById('global-msg-input');
      const content = input.value.trim();
      if (!content) return;
      input.value = '';
      await fetch('/api/global-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });
      loadGlobalChat();
    }

    // --- PROFILE ---
    async function renderProfileView(userId) {
      const root = document.getElementById('app-root');
      const res = await fetch('/api/users/' + userId);
      if (!res.ok) { root.innerHTML = '<div style="text-align:center; padding:40px;">User not found</div>'; return; }
      const { user } = await res.json();
      const isMe = currentUser && currentUser.id === user.id;

      root.innerHTML = \`
        <div style="max-width:700px; margin:0 auto; display:flex; flex-direction:column; gap:20px;">
          <div class="glass-card" style="display:flex; justify-content:space-between; align-items:flex-start;">
            <div style="display:flex; gap:16px; align-items:center;">
              <div style="width:56px; height:56px; border-radius:12px; background:#6366f1; font-size:1.5rem; font-weight:bold; color:white; display:flex; align-items:center; justify-content:center;">\${user.name.slice(0, 1).toUpperCase()}</div>
              <div>
                <h1 style="font-size:1.5rem; font-weight:bold;">\${escapeHtml(user.name)}</h1>
                \${user.school ? \`<div class="text-muted text-sm">🎓 \${escapeHtml(user.school)}</div>\` : ''}
              </div>
            </div>
            \${isMe ? \`<button onclick="editProfile()" class="btn btn-secondary btn-sm">Edit</button>\` : ''}
          </div>
          <div class="glass-card" style="display:flex; flex-direction:column; gap:12px;">
            <h3 style="font-weight:600;">Projects (\${user.projects ? user.projects.length : 0})</h3>
            <div class="grid" style="grid-template-columns:1fr;">
              \${user.projects && user.projects.length > 0 ? user.projects.map(p => \`
                <div onclick="navigate('project', '\${p.id}')" style="background:#111827; padding:12px; border-radius:8px; cursor:pointer;">
                  <div style="font-weight:500;">\${escapeHtml(p.name)}</div>
                  <div class="text-muted text-xs">\${escapeHtml(p.description)}</div>
                </div>
              \`).join('') : '<div class="text-muted text-xs">No projects yet.</div>'}
            </div>
          </div>
        </div>
      \`;
    }

    function editProfile() {
      const bio = prompt("Update bio:", currentUser.bio || "");
      if (bio === null) return;
      const school = prompt("Update school:", currentUser.school || "");
      fetch('/api/users/' + currentUser.id, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bio, school })
      }).then(async () => {
        await checkAuth();
        renderProfileView(currentUser.id);
      });
    }

    // --- AUTH (LOGIN/REGISTER) ---
    function renderLoginView() {
      const root = document.getElementById('app-root');
      root.innerHTML = \`
        <div class="glass-card" style="max-width:400px; margin:40px auto; display:flex; flex-direction:column; gap:16px;">
          <h2 style="font-size:1.5rem; font-weight:bold; text-align:center;">Sign In</h2>
          <form onsubmit="handleLogin(event)" style="display:flex; flex-direction:column; gap:12px;">
            <div>
              <label class="text-xs" style="margin-bottom:4px; display:block;">Email</label>
              <input id="login-email" type="email" required value="alex@example.com" />
            </div>
            <div>
              <label class="text-xs" style="margin-bottom:4px; display:block;">Password</label>
              <input id="login-password" type="password" required value="password123" />
            </div>
            <button type="submit" class="btn btn-primary" style="margin-top:8px;">Sign In</button>
          </form>
          <div style="text-align:center; font-size:0.75rem; color:#9ca3af;">
            Don't have an account? <button onclick="navigate('register')" class="btn btn-secondary btn-sm">Sign Up</button>
          </div>
        </div>
      \`;
    }

    async function handleLogin(e) {
      e.preventDefault();
      const email = document.getElementById('login-email').value;
      const password = document.getElementById('login-password').value;
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (res.ok) {
        currentUser = data.user;
        renderNavAuth();
        showToast('Welcome back, ' + currentUser.name + '!');
        navigate('explore');
      } else {
        showToast(data.error || 'Login failed', true);
      }
    }

    function renderRegisterView() {
      const root = document.getElementById('app-root');
      root.innerHTML = \`
        <div class="glass-card" style="max-width:400px; margin:40px auto; display:flex; flex-direction:column; gap:16px;">
          <h2 style="font-size:1.5rem; font-weight:bold; text-align:center;">Create Account</h2>
          <form onsubmit="handleRegister(event)" style="display:flex; flex-direction:column; gap:12px;">
            <div>
              <label class="text-xs" style="margin-bottom:4px; display:block;">Name</label>
              <input id="reg-name" required placeholder="Alex Rivera" />
            </div>
            <div>
              <label class="text-xs" style="margin-bottom:4px; display:block;">Email</label>
              <input id="reg-email" type="email" required placeholder="alex@example.com" />
            </div>
            <div>
              <label class="text-xs" style="margin-bottom:4px; display:block;">Password</label>
              <input id="reg-password" type="password" required placeholder="••••••••" />
            </div>
            <div>
              <label class="text-xs" style="margin-bottom:4px; display:block;">School / Institution</label>
              <input id="reg-school" placeholder="MIT, Stanford, etc." />
            </div>
            <button type="submit" class="btn btn-primary" style="margin-top:8px;">Sign Up</button>
          </form>
          <div style="text-align:center; font-size:0.75rem; color:#9ca3af;">
            Already registered? <button onclick="navigate('login')" class="btn btn-secondary btn-sm">Sign In</button>
          </div>
        </div>
      \`;
    }

    async function handleRegister(e) {
      e.preventDefault();
      const name = document.getElementById('reg-name').value;
      const email = document.getElementById('reg-email').value;
      const password = document.getElementById('reg-password').value;
      const school = document.getElementById('reg-school').value;
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password, school })
      });
      const data = await res.json();
      if (res.ok) {
        currentUser = data.user;
        renderNavAuth();
        showToast('Account created!');
        navigate('explore');
      } else {
        showToast(data.error || 'Registration failed', true);
      }
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/[&<>"']/g, function(m) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
      });
    }

    init();
  </script>
</body>
</html>`;
}

// Start standalone server on Port 5000 (or Railway process.env.PORT)
loadDB();
server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n======================================================`);
  console.log(`🚀 Pronnect Standalone Server running WITHOUT npm!`);
  console.log(`👉 Host: http://0.0.0.0:${PORT}`);
  console.log(`👉 Local: http://localhost:${PORT}`);
  console.log(`======================================================\n`);
});

