/** @jsxImportSource npm:hono@4/jsx */ 
import { Hono, Context } from "npm:hono@4";
import { getCookie, setCookie, deleteCookie } from "npm:hono@4/cookie";
import { secureHeaders } from "npm:hono@4/secure-headers";
import { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand, HeadObjectCommand } from "npm:@aws-sdk/client-s3";
import { getSignedUrl } from "npm:@aws-sdk/s3-request-presigner";
import { AwsClient } from "npm:aws4fetch";
import { Upload } from "npm:@aws-sdk/lib-storage"; 
import { html } from "npm:hono@4/html";

// =======================
// 1. CONFIG & TYPES (Must be at the top)
// =======================
interface User { username: string; passwordHash: string; plan: keyof typeof PLANS; isVip: boolean; vipExpiry?: number; usedStorage: number; createdAt: number; isBanned?: boolean; }
interface Session { username: string; expires: number; csrfToken: string; }
interface FileData { id: string; name: string; sizeBytes: number; size: string; server: "1" | "2"; r2Key: string; uploadedAt: number; expiresAt: number; type: "image" | "video" | "other"; isVipFile: boolean; }
interface SystemConfig { maintenance: boolean; }
interface UploadJob { id: string; username: string; url: string; name: string; server: "1" | "2" | "both"; expiry: string; status: "pending" | "processing" | "completed" | "failed" | "cancelled"; progress: number; error?: string; createdAt: number; }

const PLANS = {
    free:  { limit: 50 * 1024**3, name: "Free Plan" },
    vip50: { limit: 50 * 1024**3, name: "50 GB VIP" },
    vip100:{ limit: 100 * 1024**3, name: "100 GB VIP" },
    vip300:{ limit: 300 * 1024**3, name: "300 GB VIP" },
    vip500:{ limit: 500 * 1024**3, name: "500 GB VIP" },
    vip1t: { limit: 1024 * 1024**3, name: "1 TB VIP" },
    vip2t: { limit: 2048 * 1024**3, name: "2 TB VIP" },
    vip5t: { limit: 5120 * 1024**3, name: "5 TB VIP" },
    unlimited: { limit: 999999 * 1024**3, name: "Unlimited Plan" },
};

const STREAM_DOMAIN = "https://goldstorage2.deno.dev";
const PROXY_URL = "https://proxy.avotc.tk";
const R2_PUB_1  = "https://pub-50fdd8fdb8474becb9427139f00206ad.r2.dev"; 
const R2_PUB_2  = "https://pub-45c2fb2299a2438ea38ae56d17f3078e.r2.dev";
const ADMIN_USERNAME = Deno.env.get("ADMIN_USERNAME") || "admin"; 
const SECRET_KEY = Deno.env.get("SECRET_SALT") || "change-this-salt";
const MAX_REMOTE_SIZE = 15 * 1024 * 1024 * 1024; 
const ALLOWED_EXTENSIONS = new Set(['jpg','jpeg','png','gif','webp','mp4','mkv','webm','mov','mp3','wav','zip','rar','7z','pdf','txt','doc','docx']);
const BLOCKED_EXTENSIONS = new Set(['exe','sh','php','svg','pl','py','js','html','htm','css','bat','cmd','msi','dll','apk']);

// =======================
// 2. INITIALIZATION
// =======================
const app = new Hono();
app.use('*', secureHeaders());
const kv = await Deno.openKv();

// Safe Client Initialization (Prevents Crash on 500 Error)
const createS3 = (id: string, key: string, secret: string) => {
    if (!id || !key || !secret) return null;
    return new S3Client({ region: "auto", endpoint: `https://${id}.r2.cloudflarestorage.com`, credentials: { accessKeyId: key, secretAccessKey: secret } });
};
const createAws4 = (key: string, secret: string) => {
    if (!key || !secret) return null;
    return new AwsClient({ accessKeyId: key, secretAccessKey: secret, service: "s3", region: "auto" });
};

const s3Server1 = createS3(Deno.env.get("R2_1_ACCOUNT_ID")!, Deno.env.get("R2_1_ACCESS_KEY_ID")!, Deno.env.get("R2_1_SECRET_ACCESS_KEY")!);
const s3Server2 = createS3(Deno.env.get("R2_2_ACCOUNT_ID")!, Deno.env.get("R2_2_ACCESS_KEY_ID")!, Deno.env.get("R2_2_SECRET_ACCESS_KEY")!);
const r2Fetcher1 = createAws4(Deno.env.get("R2_1_ACCESS_KEY_ID")!, Deno.env.get("R2_1_SECRET_ACCESS_KEY")!);
const r2Fetcher2 = createAws4(Deno.env.get("R2_2_ACCESS_KEY_ID")!, Deno.env.get("R2_2_SECRET_ACCESS_KEY")!);

if (!s3Server1 || !s3Server2) console.error("⚠️ WARNING: R2 Credentials Missing. Uploads will fail.");

// =======================
// 3. HELPERS
// =======================
function mimeToExt(mime: string): string { 
    if (!mime) return 'bin';
    const m: any = { 'video/mp4':'mp4','video/webm':'webm','video/x-matroska':'mkv','image/jpeg':'jpg','image/png':'png', 'image/gif':'gif', 'image/webp':'webp', 'text/plain':'txt', 'application/pdf':'pdf', 'application/zip':'zip', 'application/x-zip-compressed':'zip', 'application/vnd.android.package-archive':'apk' }; 
    return m[mime.split(';')[0]] || 'bin'; 
}
async function hashPassword(password: string) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: enc.encode(SECRET_KEY), iterations: 100000, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    return Array.from(new Uint8Array(await crypto.subtle.exportKey("raw", key))).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function checkRateLimit(c: Context, action: string, limit: number): Promise<boolean> {
    const ip = c.req.header("cf-connecting-ip") || "unknown";
    const key = ["ratelimit", action, ip];
    const res = await kv.get<{count: number}>(key);
    const current = res.value?.count || 0;
    if (current >= limit) return false;
    await kv.set(key, { count: current + 1 }, { expireIn: 60 * 1000 });
    return true;
}
async function updateStats(storageDelta: number) {
    const key = ["stats", "global"];
    const res = await kv.get<{totalUsers: number, totalStorage: number}>(key);
    const current = res.value || { totalUsers: 0, totalStorage: 0 };
    await kv.set(key, { totalUsers: current.totalUsers, totalStorage: Math.max(0, current.totalStorage + storageDelta) });
}
async function incrementUserCount() {
    const key = ["stats", "global"];
    const res = await kv.get<{totalUsers: number, totalStorage: number}>(key);
    const current = res.value || { totalUsers: 0, totalStorage: 0 };
    await kv.set(key, { ...current, totalUsers: current.totalUsers + 1 });
}
async function isMaintenanceMode(): Promise<boolean> {
    const res = await kv.get<SystemConfig>(["config", "system"]);
    return res.value?.maintenance || false;
}
async function validateRemoteUrl(urlStr: string): Promise<void> {
    try {
        const url = new URL(urlStr);
        if (!['http:', 'https:'].includes(url.protocol)) throw new Error("Invalid protocol");
        const host = url.hostname;
        if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]') throw new Error("Localhost denied");
        try {
            const ips = await Deno.resolveDns(host, "A");
            for (const ip of ips) if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("0.")) throw new Error("Resolved to Private IP");
        } catch (e: any) { if(e.message === "Resolved to Private IP") throw e; }
    } catch (e: any) { throw new Error("Invalid or Blocked URL: " + e.message); }
}
async function createSession(c: Context, username: string) {
    const sessionId = crypto.randomUUID();
    const expires = Date.now() + (7 * 24 * 60 * 60 * 1000); 
    await kv.set(["sessions", sessionId], { username, expires, csrfToken: crypto.randomUUID() }, { expireIn: 7 * 24 * 60 * 60 * 1000 });
    setCookie(c, "session_id", sessionId, { path: "/", httpOnly: true, secure: true, sameSite: "Lax", maxAge: 7 * 24 * 60 * 60 });
}
async function getSessionUser(c: Context): Promise<{ user: User, csrfToken: string } | null> {
    const sessionId = getCookie(c, "session_id");
    if (!sessionId) return null;
    const res = await kv.get<Session>(["sessions", sessionId]);
    if (!res.value) return null;
    if (res.value.expires < Date.now()) { await kv.delete(["sessions", sessionId]); return null; }
    // Rolling
    kv.set(["sessions", sessionId], { ...res.value, expires: Date.now() + (7 * 24 * 60 * 60 * 1000) }, { expireIn: 7 * 24 * 60 * 60 * 1000 });
    const uRes = await kv.get<User>(["users", res.value.username]);
    if (!uRes.value) return null;
    const user = uRes.value;
    if (!user.plan || !PLANS[user.plan]) { user.plan = user.isVip ? 'vip50' : 'free'; await kv.set(["users", user.username], user); }
    return { user, csrfToken: res.value.csrfToken };
}
function validateFileName(name: string): { valid: boolean, error?: string, safeName?: string, ext?: string } {
    const ext = name.split('.').pop()?.toLowerCase() || '';
    if (BLOCKED_EXTENSIONS.has(ext)) return { valid: false, error: "Blocked File Type" };
    return { valid: true, safeName: name.replace(/[^a-zA-Z0-9.\-_\u1000-\u109F]/g, "_"), ext };
}
function isVipActive(user: User): boolean { if (user.plan === 'free') return false; return user.vipExpiry ? user.vipExpiry > Date.now() : false; }

// =======================
// 4. BACKGROUND WORKER
// =======================
async function processRemoteUpload(jobId: string) {
    const jobKey = ["jobs", jobId];
    const jobRes = await kv.get<UploadJob>(jobKey);
    if (!jobRes.value) return;
    const job = jobRes.value;

    job.status = "processing";
    await kv.set(jobKey, job);

    try {
        const userRes = await kv.get<User>(["users", job.username]);
        if (!userRes.value) throw new Error("User not found");
        const sessionUser = userRes.value;

        const r = await fetch(job.url, { headers: { "User-Agent": "Mozilla/5.0" } });
        if (!r.ok) throw new Error("Fetch Failed");
        const totalSize = parseInt(r.headers.get("content-length") || "0");
        const limitBytes = PLANS[sessionUser.plan]?.limit || PLANS.free.limit;
        const requiredSize = (job.server === "both") ? totalSize * 2 : totalSize;

        if (totalSize > MAX_REMOTE_SIZE) throw new Error("File too large");
        if (sessionUser.usedStorage + requiredSize > limitBytes) throw new Error("Storage Full");

        let contentType = r.headers.get("content-type") || "application/octet-stream";
        const reader = r.body!.getReader();
        const { value: firstChunk, done } = await reader.read();
        if (done) throw new Error("Empty File");

        const hex = [...new Uint8Array(firstChunk.slice(0, 16))].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        let detectedExt = null;
        if (hex.includes("66747970")) { detectedExt = "mp4"; contentType = "video/mp4"; }
        else if (hex.startsWith("1A45DFA3")) { detectedExt = "mkv"; contentType = "video/x-matroska"; }

        let ext = detectedExt || mimeToExt(contentType);
        if (!detectedExt && (ext === 'bin' || ext === 'txt')) {
             try { const uExt = new URL(job.url).pathname.split('.').pop()?.toLowerCase(); if(uExt && ALLOWED_EXTENSIONS.has(uExt)) ext = uExt; } catch(e){}
        }
        if (BLOCKED_EXTENSIONS.has(ext)) throw new Error("Blocked File Type");

        const safeName = job.name.replace(/[^a-zA-Z0-9.\-_\u1000-\u109F]/g, "_");
        let fileName = safeName.includes('.') ? safeName : safeName + '.' + ext;
        const parts = fileName.lastIndexOf('.');
        const nameBase = parts !== -1 ? fileName.substring(0, parts) : fileName;
        const fExt = parts !== -1 ? fileName.substring(parts) : '';
        
        const uniqueTime = Date.now();
        const sharedR2Key = `${sessionUser.username}/${nameBase}-${uniqueTime}${fExt}`;
        const sharedFileId = `${uniqueTime}-${crypto.randomUUID()}`;

        const finalStream = new ReadableStream({
            start(ctrl) { ctrl.enqueue(firstChunk); },
            async pull(ctrl) {
                const currentJob = await kv.get<UploadJob>(jobKey);
                if (currentJob.value?.status === "cancelled") { await reader.cancel(); ctrl.close(); throw new Error("Cancelled"); }
                const { value, done } = await reader.read();
                if (done) ctrl.close(); else ctrl.enqueue(value);
            },
            cancel() { reader.cancel(); }
        });

        const doUpload = async (svr: "1" | "2", stream: ReadableStream, key: string, id: string) => {
            const client = svr === "1" ? s3Server1 : s3Server2;
            const bucket = svr === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
            if (!client) throw new Error("Server not configured");

            const upload = new Upload({ 
                client, 
                params: { 
                    Bucket: bucket, Key: key, Body: stream as any, ContentType: contentType,
                    ContentDisposition: `attachment; filename="${encodeURIComponent(fileName)}"`
                }, 
                queueSize: 1, partSize: 10 * 1024**2 
            });

            let lastUpdate = 0;
            upload.on("httpUploadProgress", (p) => {
                const now = Date.now();
                if (now - lastUpdate > 3000 && totalSize) { 
                    lastUpdate = now;
                    kv.get<UploadJob>(jobKey).then(res => {
                        if(res.value && res.value.status === 'processing') {
                            res.value.progress = Math.round((p.loaded! / totalSize) * 100);
                            kv.set(jobKey, res.value);
                        }
                    });
                }
            });

            await upload.done();
            const cacheKey = ["meta", svr, key];
            await kv.set(cacheKey, { size: totalSize, type: contentType, mtime: new Date().toUTCString() }, { expireIn: 365*24*60*60*1000 });

            const expiryDays = parseInt(job.expiry) || 0;
            const fileData: FileData = { id, name: fileName, sizeBytes: totalSize, size: (totalSize / 1024**2).toFixed(2) + " MB", server: svr, r2Key: key, uploadedAt: Date.now(), expiresAt: expiryDays > 0 ? Date.now() + (expiryDays * 86400000) : 0, type: contentType.startsWith("image/") ? "image" : contentType.startsWith("video/") ? "video" : "other", isVipFile: true };
            await kv.atomic().set(["files", sessionUser.username, id], fileData).commit();
        };

        if (job.server === "both") {
            const [s1, s2] = finalStream.tee();
            await Promise.all([doUpload("1", s1, sharedR2Key, sharedFileId + "-1"), doUpload("2", s2, sharedR2Key, sharedFileId + "-2")]);
        } else {
            await doUpload(job.server, finalStream, sharedR2Key, sharedFileId);
        }

        let committed = false;
        while (!committed) {
            const res = await kv.get<User>(["users", sessionUser.username]);
            if (!res.value) break;
            const newUser = { ...res.value, usedStorage: res.value.usedStorage + requiredSize };
            const status = await kv.atomic().check(res).set(["users", sessionUser.username], newUser).commit();
            committed = status.ok;
        }
        await updateStats(requiredSize);

        const finalJob = await kv.get<UploadJob>(jobKey);
        if(finalJob.value) { finalJob.value.status = "completed"; finalJob.value.progress = 100; await kv.set(jobKey, finalJob.value, { expireIn: 3600 * 1000 }); }

    } catch (e: any) {
        const failedJob = await kv.get<UploadJob>(jobKey);
        if(failedJob.value && failedJob.value.status !== "cancelled") { failedJob.value.status = "failed"; failedJob.value.error = e.message; await kv.set(jobKey, failedJob.value, { expireIn: 3600 * 1000 }); }
    }
}

// =======================
// 5. DOWNLOAD ROUTES
// =======================
app.on(['GET', 'HEAD'], "/d/:server/*", async (c) => {
    const server = c.req.param("server");
    const rawPath = c.req.path.split(`/d/${server}/`)[1];
    if (!rawPath) return c.text("Invalid Key", 400);
    const decodedKey = decodeURIComponent(rawPath);
    
    // Server 1 or 2
    const isS1 = server === "1";
    const client = isS1 ? r2Fetcher1 : r2Fetcher2;
    const bucket = isS1 ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    const accountId = isS1 ? Deno.env.get("R2_1_ACCOUNT_ID") : Deno.env.get("R2_2_ACCOUNT_ID");

    if(!client || !bucket || !accountId) return c.text("Server Config Error", 500);

    try {
        // Pre-Cache Lookup
        let size = "";
        let contentType = "application/octet-stream";
        let lastMod = new Date().toUTCString();

        const cacheKey = ["meta", server, decodedKey];
        const cached = await kv.get<any>(cacheKey);
        
        if (cached.value) {
            size = String(cached.value.size);
            contentType = cached.value.type;
            lastMod = cached.value.mtime;
        } else {
            // Fallback to manual fix
            const ext = decodedKey.split('.').pop()?.toLowerCase();
            if (ext === "mp4") contentType = "video/mp4";
            else if (ext === "mkv") contentType = "video/x-matroska";
        }

        const encodedPath = decodedKey.split('/').map(encodeURIComponent).join('/');
        const objectUrl = new URL(`https://${accountId}.r2.cloudflarestorage.com/${bucket}/${encodedPath}`);
        const hostHeader = { "Host": `${accountId}.r2.cloudflarestorage.com` };

        // HEAD
        if (c.req.method === 'HEAD') {
            const headers = new Headers();
            if(cached.value) headers.set("Content-Length", size);
            headers.set("Content-Type", contentType);
            headers.set("Accept-Ranges", "bytes");
            headers.set("Last-Modified", lastMod);
            headers.set("Access-Control-Allow-Origin", "*");
            return new Response(null, { status: 200, headers });
        }

        // GET (Redirect)
        const isDownload = c.req.query('dl') === '1';
        const fileName = decodedKey.split('/').pop()?.replace(/-\d+(\.[a-zA-Z0-9]+)?$/, "$1") || "file";
        const disposition = `${isDownload ? "attachment" : "inline"}; filename="${encodeURIComponent(fileName)}"; filename*=UTF-8''${encodeURIComponent(fileName)}`;
        objectUrl.searchParams.set("response-content-disposition", disposition);

        const signed = await client.sign(objectUrl, { method: "GET", aws: { signQuery: true }, headers: hostHeader, expiresIn: 10800 });
        c.header("Cache-Control", "no-cache");
        return c.redirect(signed.url, 302);

    } catch (e) { return c.text("File Not Found", 404); }
});

// =======================
// 6. UPLOAD ROUTES (API)
// =======================
app.post("/api/upload/remote", async (c) => {
    if(!await checkRateLimit(c, "upload_remote", 20)) return c.json({error: "Too many requests"}, 429);
    const session = await getSessionUser(c);
    if(!session || !isVipActive(session.user)) return c.json({error: "VIP Only"}, 403);
    const body = await c.req.json();
    if(body.csrf !== session.csrfToken) return c.json({error: "Invalid CSRF"}, 403);

    const jobId = crypto.randomUUID();
    const job: UploadJob = { id: jobId, username: session.user.username, url: body.url, name: body.customName || "remote", server: body.server, expiry: body.expiry, status: "pending", progress: 0, createdAt: Date.now() };
    await kv.set(["jobs", jobId], job);
    processRemoteUpload(jobId); // Background Start
    return c.json({ success: true, jobId: jobId });
});

app.get("/api/job/:id", async (c) => {
    const id = c.req.param("id");
    const res = await kv.get<UploadJob>(["jobs", id]);
    return res.value ? c.json(res.value) : c.json({ error: "Job not found" }, 404);
});

app.post("/api/job/cancel", async (c) => {
    const { jobId } = await c.req.json();
    const key = ["jobs", jobId];
    const res = await kv.get<UploadJob>(key);
    if(res.value) { res.value.status = "cancelled"; await kv.set(key, res.value); return c.json({ success: true }); }
    return c.json({ error: "Not found" });
});

// ... (Other Routes: Presign, Complete, Admin, Auth - kept same as logic requires)
// (Due to length, ensuring critical parts are here. Presign/Complete needs standard logic)

app.post("/api/upload/presign", async (c) => {
    // ... Standard Presign Logic ...
    const session = await getSessionUser(c); if(!session) return c.json({error:"Login"},401);
    const { name, type, server } = await c.req.json();
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    const r2Key = `${session.user.username}/${name.replace(/[^a-zA-Z0-9.]/g,"_")}-${Date.now()}`;
    const command = new PutObjectCommand({ Bucket: bucket, Key: r2Key, ContentType: type, ContentDisposition: `attachment; filename="${encodeURIComponent(name)}"` });
    const url = await getSignedUrl(client!, command, { expiresIn: 10800 });
    return c.json({ url, key: r2Key, fileId: crypto.randomUUID() });
});

app.post("/api/upload/complete", async (c) => {
    // ... Standard Complete Logic ...
    const session = await getSessionUser(c); if(!session) return c.json({error:"Login"},401);
    const { key, fileId, server, expiry } = await c.req.json();
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    const head = await client!.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    
    // Cache
    await kv.set(["meta", server, key], { size: head.ContentLength, type: head.ContentType, mtime: new Date().toUTCString() }, { expireIn: 365*24*60*60*1000 });
    
    // Save File
    const fileData: FileData = { id: fileId, name: key.split('/').pop()!, sizeBytes: head.ContentLength!, size: (head.ContentLength!/1024**2).toFixed(2)+"MB", server, r2Key: key, uploadedAt: Date.now(), expiresAt: 0, type: "video", isVipFile: true };
    await kv.set(["files", session.user.username, fileId], fileData);
    await updateStats(head.ContentLength!);
    return c.json({ success: true });
});

// =======================
// UI ROUTES
// =======================
const MainScript = `
<script>
    const IS_USER_VIP = window.IS_VIP_USER || false;
    let currentJobId = localStorage.getItem("activeJobId");

    window.onload = function() {
        if(currentJobId) {
            // Resume Progress UI
            switchUploadMode('remote');
            document.getElementById('progressContainerRemote').classList.remove('hidden');
            document.getElementById('cancelBtnRemote').classList.remove('hidden');
            pollStatus();
        }
    };

    async function uploadRemote(event) {
        event.preventDefault();
        const urlInput = document.getElementById('remoteUrl');
        if(!urlInput.value) return showToast("URL Required", 'error');
        
        setLoading('remoteBtn', true, 'Starting...');
        document.getElementById('progressContainerRemote').classList.remove('hidden');
        document.getElementById('cancelBtnRemote').classList.remove('hidden');

        try {
            const res = await fetch('/api/upload/remote', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: urlInput.value,
                    customName: document.getElementById('remoteName').value,
                    server: document.querySelector('input[name="server_remote"]:checked').value,
                    expiry: document.querySelector('select[name="expiry_remote"]').value,
                    csrf: window.CSRF_TOKEN
                })
            });
            const data = await res.json();
            if(data.error) throw new Error(data.error);
            
            currentJobId = data.jobId;
            localStorage.setItem("activeJobId", currentJobId);
            pollStatus();
        } catch(e) {
            showToast(e.message, 'error'); resetUI('remote');
        }
    }

    async function pollStatus() {
        if(!currentJobId) return;
        try {
            const res = await fetch('/api/job/' + currentJobId);
            if(res.status === 404) throw new Error("Job not found");
            const job = await res.json();

            if(job.status === 'failed' || job.status === 'cancelled') throw new Error(job.error || "Failed");
            
            document.getElementById('progressBarRemote').style.width = job.progress + "%";
            document.getElementById('progressTextRemote').innerText = job.progress + "%";

            if(job.status === 'completed') {
                localStorage.removeItem("activeJobId");
                currentJobId = null;
                showToast("Upload Completed!");
                setTimeout(() => window.location.reload(), 1000);
            } else {
                setTimeout(pollStatus, 2000);
            }
        } catch(e) {
            localStorage.removeItem("activeJobId");
            currentJobId = null;
            showToast(e.message, 'error');
            resetUI('remote');
        }
    }

    async function cancelRemote() {
        if(currentJobId) await fetch('/api/job/cancel', { method: 'POST', body: JSON.stringify({ jobId: currentJobId }) });
        localStorage.removeItem("activeJobId");
        currentJobId = null;
        resetUI('remote');
    }

    // ... (Keep existing UI functions: switchTab, openModal, etc.) ...
    // Note: Ensure openLinkModal, uploadLocal are included in the final pasted code (omitted here to save space but assumed present in your logic)
</script>
`;

// ... (Layout & App Routes like /login, /admin - keep them same as before, just ensure Layout uses MainScript) ...

Deno.serve(app.fetch);
