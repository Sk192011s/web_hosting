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
// 1. CONFIGURATION & ENV CHECK
// =======================
const REQUIRED_ENVS = ["R2_1_ACCOUNT_ID", "R2_1_ACCESS_KEY_ID", "R2_1_SECRET_ACCESS_KEY", "R2_1_BUCKET_NAME", "ADMIN_USERNAME", "SECRET_SALT"];
const MISSING_ENVS = REQUIRED_ENVS.filter(k => !Deno.env.get(k));
if (MISSING_ENVS.length > 0) {
    console.error(`❌ Missing ENV Variables: ${MISSING_ENVS.join(", ")}`);
}

const app = new Hono();
app.use('*', secureHeaders());

const kv = await Deno.openKv();

// 🔥 CONFIGS 🔥
const STREAM_DOMAIN = "https://goldstorage2.deno.dev";
const PROXY_URL = "https://proxy.avotc.tk";
const R2_PUB_1  = "https://pub-50fdd8fdb8474becb9427139f00206ad.r2.dev"; 
const R2_PUB_2  = "https://pub-45c2fb2299a2438ea38ae56d17f3078e.r2.dev";

const ADMIN_USERNAME = Deno.env.get("ADMIN_USERNAME") || "admin"; 
const SECRET_KEY = Deno.env.get("SECRET_SALT") || "change-this-secret-salt-immediately";
const MAX_REMOTE_SIZE = 15 * 1024 * 1024 * 1024; // 15 GB
const ALLOWED_EXTENSIONS = new Set(['jpg','jpeg','png','gif','webp','mp4','mkv','webm','mov','mp3','wav','zip','rar','7z','pdf','txt','doc','docx']);
const BLOCKED_EXTENSIONS = new Set(['exe','sh','php','svg','pl','py','js','html','htm','css','bat','cmd','msi','dll','apk']);

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

// =======================
// GLOBAL CLIENTS (Connection Pool)
// =======================
const s3Server1 = new S3Client({
  region: "auto", endpoint: `https://${Deno.env.get("R2_1_ACCOUNT_ID")}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: Deno.env.get("R2_1_ACCESS_KEY_ID")!, secretAccessKey: Deno.env.get("R2_1_SECRET_ACCESS_KEY")! },
});
const s3Server2 = new S3Client({
  region: "auto", endpoint: `https://${Deno.env.get("R2_2_ACCOUNT_ID")}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: Deno.env.get("R2_2_ACCESS_KEY_ID")!, secretAccessKey: Deno.env.get("R2_2_SECRET_ACCESS_KEY")! },
});
// aws4fetch clients for download
const r2Fetcher1 = new AwsClient({ accessKeyId: Deno.env.get("R2_1_ACCESS_KEY_ID")!, secretAccessKey: Deno.env.get("R2_1_SECRET_ACCESS_KEY")!, service: "s3", region: "auto" });
const r2Fetcher2 = new AwsClient({ accessKeyId: Deno.env.get("R2_2_ACCESS_KEY_ID")!, secretAccessKey: Deno.env.get("R2_2_SECRET_ACCESS_KEY")!, service: "s3", region: "auto" });

// =======================
// 2. BACKGROUND WORKER & TYPES
// =======================
interface User { username: string; passwordHash: string; plan: keyof typeof PLANS; isVip: boolean; vipExpiry?: number; usedStorage: number; createdAt: number; isBanned?: boolean; }
interface Session { username: string; expires: number; csrfToken: string; }
interface FileData { id: string; name: string; sizeBytes: number; size: string; server: "1" | "2"; r2Key: string; uploadedAt: number; expiresAt: number; type: "image" | "video" | "other"; isVipFile: boolean; }
interface SystemConfig { maintenance: boolean; }

// 🔥 Job Interface 🔥
interface UploadJob {
    id: string; username: string; url: string; name: string; server: "1" | "2" | "both"; 
    expiry: string; status: "pending" | "processing" | "completed" | "failed" | "cancelled";
    progress: number; error?: string; createdAt: number;
}

// 🔥 Background Worker Function 🔥
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

        // Fetch URL
        const r = await fetch(job.url, { 
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" } 
        });
        if (!r.ok) throw new Error("Fetch Failed: " + r.statusText);
        
        const totalSize = parseInt(r.headers.get("content-length") || "0");
        const limitBytes = PLANS[sessionUser.plan]?.limit || PLANS.free.limit;
        const requiredSize = (job.server === "both") ? totalSize * 2 : totalSize;

        if (totalSize > MAX_REMOTE_SIZE) throw new Error(`File too large (Limit: ${(MAX_REMOTE_SIZE/1024**3).toFixed(0)}GB)`);
        if (sessionUser.usedStorage + requiredSize > limitBytes) throw new Error("Storage Full");

        // Magic Number & Extension Logic
        let contentType = r.headers.get("content-type") || "application/octet-stream";
        const reader = r.body!.getReader();
        const { value: firstChunk, done } = await reader.read();
        if (done) throw new Error("Empty File");

        const hex = [...new Uint8Array(firstChunk.slice(0, 16))].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        let detectedExt = null;
        if (hex.includes("66747970")) { detectedExt = "mp4"; contentType = "video/mp4"; }
        else if (hex.startsWith("1A45DFA3")) { detectedExt = "mkv"; contentType = "video/x-matroska"; }
        else if (hex.startsWith("52494646")) { detectedExt = "avi"; contentType = "video/x-msvideo"; }

        let ext = detectedExt || mimeToExt(contentType);
        if (!detectedExt && (ext === 'bin' || ext === 'txt')) {
             try { const uExt = new URL(job.url).pathname.split('.').pop()?.toLowerCase(); if(uExt && ALLOWED_EXTENSIONS.has(uExt)) ext = uExt; } catch(e){}
        }
        if (BLOCKED_EXTENSIONS.has(ext)) throw new Error("Blocked File Type");

        // Shared Key Gen
        const safeName = job.name.replace(/[^a-zA-Z0-9.\-_\u1000-\u109F]/g, "_");
        let fileName = safeName.includes('.') ? safeName : safeName + '.' + ext;
        const parts = fileName.lastIndexOf('.');
        const nameBase = parts !== -1 ? fileName.substring(0, parts) : fileName;
        const fExt = parts !== -1 ? fileName.substring(parts) : '';
        const uniqueTime = Date.now();
        const sharedR2Key = `${sessionUser.username}/${nameBase}-${uniqueTime}${fExt}`;
        const sharedFileId = `${uniqueTime}-${crypto.randomUUID()}`;

        // Stream Reconstruction
        const finalStream = new ReadableStream({
            start(ctrl) { ctrl.enqueue(firstChunk); },
            async pull(ctrl) {
                const currentJob = await kv.get<UploadJob>(jobKey);
                if (currentJob.value?.status === "cancelled") {
                    await reader.cancel(); ctrl.close(); throw new Error("Cancelled");
                }
                const { value, done } = await reader.read();
                if (done) ctrl.close(); else ctrl.enqueue(value);
            },
            cancel() { reader.cancel(); }
        });

        // Upload Function
        const doUpload = async (svr: "1" | "2", stream: ReadableStream, key: string, id: string) => {
            const client = svr === "1" ? s3Server1 : s3Server2;
            const bucket = svr === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
            
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
                if (now - lastUpdate > 2000 && totalSize) { // 2 sec interval
                    lastUpdate = now;
                    const percent = Math.round((p.loaded! / totalSize) * 100);
                    kv.get<UploadJob>(jobKey).then(res => {
                        if(res.value && res.value.status === 'processing') {
                            res.value.progress = percent;
                            kv.set(jobKey, res.value);
                        }
                    });
                }
            });

            await upload.done();

            // Pre-Cache & Save
            const cacheMetaKey = ["meta", svr, key];
            await kv.set(cacheMetaKey, { size: totalSize, type: contentType, mtime: new Date().toUTCString() }, { expireIn: 365*24*60*60*1000 });

            const expiryDays = parseInt(job.expiry) || 0;
            const fileData: FileData = { 
                id: id, name: fileName, sizeBytes: totalSize, 
                size: (totalSize / 1024**2).toFixed(2) + " MB", 
                server: svr, r2Key: key, 
                uploadedAt: Date.now(), 
                expiresAt: expiryDays > 0 ? Date.now() + (expiryDays * 86400000) : 0, 
                type: contentType.startsWith("image/") ? "image" : contentType.startsWith("video/") ? "video" : "other", 
                isVipFile: true 
            };
            await kv.atomic().set(["files", sessionUser.username, id], fileData).commit();
        };

        if (job.server === "both") {
            const [s1, s2] = finalStream.tee();
            await Promise.all([
                doUpload("1", s1, sharedR2Key, sharedFileId + "-1"),
                doUpload("2", s2, sharedR2Key, sharedFileId + "-2")
            ]);
        } else {
            await doUpload(job.server, finalStream, sharedR2Key, sharedFileId);
        }

        // Update Storage
        let committed = false;
        while (!committed) {
            const res = await kv.get<User>(["users", sessionUser.username]);
            if (!res.value) break;
            const newUser = { ...res.value, usedStorage: res.value.usedStorage + requiredSize };
            const status = await kv.atomic().check(res).set(["users", sessionUser.username], newUser).commit();
            committed = status.ok;
        }
        await updateStats(requiredSize);

        // Complete Job
        const finalJob = await kv.get<UploadJob>(jobKey);
        if(finalJob.value) {
            finalJob.value.status = "completed";
            finalJob.value.progress = 100;
            await kv.set(jobKey, finalJob.value, { expireIn: 3600 * 1000 });
        }

    } catch (e: any) {
        const failedJob = await kv.get<UploadJob>(jobKey);
        if(failedJob.value && failedJob.value.status !== "cancelled") {
            failedJob.value.status = "failed";
            failedJob.value.error = e.message;
            await kv.set(jobKey, failedJob.value, { expireIn: 3600 * 1000 });
        }
    }
}

// =======================
// 3. HELPERS
// =======================
async function hashPassword(password: string) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: enc.encode(SECRET_KEY), iterations: 100000, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const exported = await crypto.subtle.exportKey("raw", key);
    return Array.from(new Uint8Array(exported)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkRateLimit(c: Context, action: string, limit: number): Promise<boolean> {
    const ip = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || "unknown";
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
        if (host.startsWith('192.168.') || host.startsWith('10.') || host.match(/^172\.(1[6-9]|2\d|3[0-1])\./)) throw new Error("Private IP denied");
        try {
            const ips = await Deno.resolveDns(host, "A");
            for (const ip of ips) if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("0.")) throw new Error("Resolved to Private IP");
        } catch (e: any) { if(e.message === "Resolved to Private IP") throw e; }
    } catch (e: any) { throw new Error("Invalid or Blocked URL: " + e.message); }
}

async function createSession(c: Context, username: string) {
    const sessionId = crypto.randomUUID();
    const csrfToken = crypto.randomUUID();
    const expires = Date.now() + (7 * 24 * 60 * 60 * 1000); 
    await kv.set(["sessions", sessionId], { username, expires, csrfToken }, { expireIn: 7 * 24 * 60 * 60 * 1000 });
    setCookie(c, "session_id", sessionId, { path: "/", httpOnly: true, secure: true, sameSite: "Lax", maxAge: 7 * 24 * 60 * 60 });
}

async function getSessionUser(c: Context): Promise<{ user: User, csrfToken: string } | null> {
    const sessionId = getCookie(c, "session_id");
    if (!sessionId) return null;
    const res = await kv.get<Session>(["sessions", sessionId]);
    if (!res.value) return null;
    if (res.value.expires < Date.now()) { await kv.delete(["sessions", sessionId]); return null; }
    
    // Rolling Session
    const newExpires = Date.now() + (7 * 24 * 60 * 60 * 1000);
    kv.set(["sessions", sessionId], { ...res.value, expires: newExpires }, { expireIn: 7 * 24 * 60 * 60 * 1000 });
    
    const uRes = await kv.get<User>(["users", res.value.username]);
    if (!uRes.value) return null;
    const user = uRes.value;
    if (!user.plan || !PLANS[user.plan]) { user.plan = user.isVip ? 'vip50' : 'free'; await kv.set(["users", user.username], user); }
    return { user, csrfToken: res.value.csrfToken };
}

function validateFileName(name: string): { valid: boolean, error?: string, safeName?: string, ext?: string } {
    const ext = name.split('.').pop()?.toLowerCase() || '';
    if (BLOCKED_EXTENSIONS.has(ext)) return { valid: false, error: "Security Restriction: This file type is not allowed." };
    const safeName = name.replace(/[^a-zA-Z0-9.\-_\u1000-\u109F]/g, "_");
    return { valid: true, safeName, ext };
}

function isVipActive(user: User): boolean { if (user.plan === 'free') return false; return user.vipExpiry ? user.vipExpiry > Date.now() : false; }
function formatDate(ts: number) { return new Date(ts).toLocaleDateString('my-MM', { day: 'numeric', month: 'short', year: 'numeric' }); }
function mimeToExt(mime: string): string { 
    if (!mime) return 'bin';
    const m: any = { 'video/mp4':'mp4','video/webm':'webm','video/x-matroska':'mkv','image/jpeg':'jpg','image/png':'png', 'image/gif':'gif', 'image/webp':'webp', 'text/plain':'txt', 'application/pdf':'pdf', 'application/zip':'zip', 'application/x-zip-compressed':'zip', 'application/vnd.android.package-archive':'apk' }; 
    return m[mime.split(';')[0]] || 'bin'; 
}

// =======================
// 4. FRONTEND SCRIPTS
// =======================
const ToastScript = `
<script>
    function showToast(message, type = 'success') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        const bgColor = type === 'error' ? 'bg-red-600' : 'bg-green-600';
        const icon = type === 'error' ? '<i class="fa-solid fa-triangle-exclamation"></i>' : '<i class="fa-solid fa-check-circle"></i>';
        toast.className = \`\${bgColor} text-white px-6 py-3 rounded-xl shadow-2xl flex items-center gap-3 transform transition-all duration-300 translate-y-10 opacity-0\`;
        toast.innerHTML = \`\${icon} <span class="font-bold text-sm">\${message}</span>\`;
        container.appendChild(toast);
        requestAnimationFrame(() => { toast.classList.remove('translate-y-10', 'opacity-0'); });
        setTimeout(() => { toast.classList.add('translate-y-10', 'opacity-0'); setTimeout(() => toast.remove(), 300); }, 3000);
    }
    function setLoading(btnId, isLoading, text = 'Loading...') {
        const btn = document.getElementById(btnId);
        if(!btn) return;
        if(isLoading) {
            btn.dataset.originalText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = \`<i class="fa-solid fa-circle-notch fa-spin"></i> \${text}\`;
            btn.classList.add('opacity-75', 'cursor-not-allowed');
        } else {
            btn.disabled = false;
            btn.innerHTML = btn.dataset.originalText || 'Submit';
            btn.classList.remove('opacity-75', 'cursor-not-allowed');
        }
    }
</script>
`;

const MainScript = `
<script>
    const IS_USER_VIP = window.IS_VIP_USER || false;
    let targetFileId = null; 
    let isUploading = false; 
    
    // Background Job Tracking
    let currentJobId = localStorage.getItem("activeJobId"); // Restore job if page refresh

    window.onload = function() {
        if(currentJobId) {
            // If job exists, resume polling
            switchUploadMode('remote');
            document.getElementById('progressContainerRemote').classList.remove('hidden');
            document.getElementById('cancelBtnRemote').classList.remove('hidden');
            setLoading('remoteBtn', true, 'Uploading in background...');
            pollStatus();
        }
    };

    function switchTab(tab) {
        const url = new URL(window.location);
        url.searchParams.set('type', tab); url.searchParams.delete('cursor'); 
        window.location.href = url.toString();
    }
    
    function switchUploadMode(mode) {
        if (mode === 'remote' && !IS_USER_VIP) { document.getElementById('vipModal').classList.remove('hidden'); return; }
        document.querySelectorAll('.upload-mode').forEach(el => el.classList.add('hidden'));
        document.querySelectorAll('.mode-btn').forEach(el => { el.classList.remove('bg-yellow-500', 'text-black'); el.classList.add('bg-zinc-800', 'text-gray-400'); });
        document.getElementById('mode-' + mode).classList.remove('hidden');
        document.getElementById('btn-mode-' + mode).classList.remove('bg-zinc-800', 'text-gray-400');
        document.getElementById('btn-mode-' + mode).classList.add('bg-yellow-500', 'text-black');
    }

    function openDeleteModal(fileId) { targetFileId = fileId; document.getElementById('deleteModal').classList.remove('hidden'); }
    function openEditModal(fileId) { if (!IS_USER_VIP) return; targetFileId = fileId; document.getElementById('editModal').classList.remove('hidden'); }
    function closeModal(id) { document.getElementById(id).classList.add('hidden'); targetFileId = null; }

    async function confirmDelete() {
        if(!targetFileId) return;
        setLoading('btnConfirmDelete', true, 'ဖျက်နေသည်...');
        try {
            const formData = new FormData();
            formData.append('csrf', window.CSRF_TOKEN);
            const res = await fetch('/delete/' + targetFileId, { method: 'POST', body: formData });
            if(res.ok) { showToast('ဖိုင်ကို ဖျက်လိုက်ပါပြီ'); setTimeout(() => window.location.reload(), 1000); }
            else { throw new Error("Delete failed"); }
        } catch(e) { showToast("Error deleting file", "error"); setLoading('btnConfirmDelete', false); }
    }

    async function confirmEdit() {
        if(!targetFileId) return;
        setLoading('btnConfirmEdit', true, 'ပြင်နေသည်...');
        try {
            const res = await fetch('/api/file/edit', { 
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ fileId: targetFileId, days: document.getElementById('editExpirySelect').value, csrf: window.CSRF_TOKEN }) 
            });
            const d = await res.json();
            if(d.success) window.location.reload(); else showToast(d.error, 'error');
        } catch(e) { showToast("Error editing file", 'error'); }
        finally { setLoading('btnConfirmEdit', false); }
    }

    // Link Generator
    function openLinkModal(r2Key) {
        const modal = document.getElementById('linkModal');
        const area = document.getElementById('allLinksArea');
        if(!modal || !area) return;
        modal.classList.remove('hidden');
        
        const domain = window.STREAM_DOMAIN; 
        const proxy = window.PROXY_URL;
        const pub1 = window.R2_PUB_1;
        const pub2 = window.R2_PUB_2;

        const s1_dl = domain + "/d/1/" + r2Key + "?dl=1";
        const s1_raw = pub1 + "/" + r2Key;
        const s1_proxy = proxy + "/" + pub1 + "/" + r2Key;

        const s2_dl = domain + "/d/2/" + r2Key + "?dl=1";
        const s2_raw = pub2 + "/" + r2Key;
        const s2_proxy = proxy + "/" + pub2 + "/" + r2Key;

        const text = 
            "🛡️ [ PROXY LINKS ]\\n" + s1_proxy + "\\n" + s2_proxy + "\\n\\n" +
            "📥 [ DIRECT LINKS ]\\n" + s1_dl + "\\n" + s2_dl + "\\n\\n" +
            "🌐 [ PUBLIC LINKS ]\\n" + s1_raw + "\\n" + s2_raw;

        area.value = text;
    }

    // Local Upload
    let activeXHR = null;
    function cancelLocal() { if(activeXHR) { activeXHR.abort(); activeXHR = null; isUploading = false; resetUI('local'); showToast("Upload Cancelled", 'error'); } }
    function resetUI(mode) {
         if(mode === 'local') {
            document.getElementById('progressContainer').classList.add('hidden');
            setLoading('submitBtn', false); document.getElementById('progressBar').style.width = '0%';
         } else {
            document.getElementById('progressContainerRemote').classList.add('hidden');
            setLoading('remoteBtn', false); document.getElementById('progressBarRemote').style.width = '0%';
            currentJobId = null;
            localStorage.removeItem("activeJobId");
         }
    }

    async function uploadLocal(event) {
        event.preventDefault();
        const fileInput = document.getElementById('fileInput');
        const formData = new FormData(document.getElementById('uploadForm'));
        if(fileInput.files.length === 0) { showToast("ကျေးဇူးပြု၍ ဖိုင်ရွေးပါ", 'error'); return; }
        const file = fileInput.files[0];
        
        // Basic Check
        const slice = file.slice(0, 4);
        const buffer = await slice.arrayBuffer();
        const uint = new Uint8Array(buffer);
        let bytes = []; uint.forEach((byte) => bytes.push(byte.toString(16)));
        if (bytes.join("").toUpperCase().startsWith('4D5A')) { showToast("Security Warning (Blocked)", 'error'); return; }

        isUploading = true;
        setLoading('submitBtn', true, 'စစ်ဆေးနေသည်...');
        document.getElementById('progressContainer').classList.remove('hidden');
        document.getElementById('cancelBtnLocal').classList.remove('hidden');

        try {
            const presignRes = await fetch("/api/upload/presign", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                    name: file.name, type: file.type, size: file.size, 
                    server: formData.get("server"), customName: formData.get("customName"), csrf: window.CSRF_TOKEN 
                })
            });
            const presignData = await presignRes.json();
            if (!presignRes.ok) throw new Error(presignData.error || "Presign Error");
            const { url, key, fileId } = presignData;

            document.getElementById('submitBtn').innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Uploading...';
            activeXHR = new XMLHttpRequest();
            activeXHR.open("PUT", url, true);
            activeXHR.setRequestHeader("Content-Type", file.type); 
            
            activeXHR.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    document.getElementById('progressBar').style.width = percent + "%";
                    document.getElementById('progressText').innerText = percent + "%";
                }
            };
            activeXHR.onload = async () => {
                if (activeXHR.status === 200) {
                    document.getElementById('submitBtn').innerHTML = 'သိမ်းဆည်းနေသည်...';
                    document.getElementById('cancelBtnLocal').classList.add('hidden');
                    const compRes = await fetch("/api/upload/complete", { 
                        method: "POST", headers: { "Content-Type": "application/json" }, 
                        body: JSON.stringify({ key, fileId, server: formData.get("server"), expiry: formData.get("expiry"), csrf: window.CSRF_TOKEN }) 
                    });
                    if(!compRes.ok) throw new Error("Verification Failed");
                    document.getElementById('progressBar').classList.add('bg-green-500'); 
                    showToast('အောင်မြင်စွာ တင်ပြီးပါပြီ');
                    isUploading = false; setTimeout(() => window.location.reload(), 1000);
                } else { throw new Error("Upload Failed"); }
            };
            activeXHR.onerror = () => { throw new Error("Network Connection Error"); };
            activeXHR.send(file);
        } catch (error) { 
            if(activeXHR && activeXHR.status === 0) return;
            isUploading = false; showToast(error.message, 'error'); resetUI('local');
        }
    }

    // Remote Upload (Background Polling)
    async function uploadRemote(event) {
        event.preventDefault();
        const urlInput = document.getElementById('remoteUrl');
        if(!urlInput.value) { showToast("URL ထည့်ပေးပါ", 'error'); return; }
        
        if(currentJobId) { showToast("Already uploading a file", "error"); return; }

        isUploading = true;
        setLoading('remoteBtn', true, 'စတင်နေသည်...');
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
            localStorage.setItem("activeJobId", currentJobId); // Persist job
            pollStatus(); 

        } catch (e) {
            isUploading = false; showToast(e.message, 'error'); resetUI('remote');
        }
    }

    async function pollStatus() {
        if(!currentJobId) return;

        try {
            const res = await fetch('/api/job/' + currentJobId);
            if(res.status === 404) { throw new Error("Job not found"); }
            const job = await res.json();

            if(job.error || job.status === 'failed') throw new Error(job.error || "Upload Failed");
            if(job.status === 'cancelled') throw new Error("Cancelled by User");

            document.getElementById('progressBarRemote').style.width = job.progress + "%";
            document.getElementById('progressTextRemote').innerText = job.progress + "% (" + job.status + ")";

            if(job.status === 'completed') {
                document.getElementById('progressBarRemote').classList.add('bg-green-500');
                document.getElementById('cancelBtnRemote').classList.add('hidden');
                showToast('Upload ပြီးဆုံးပါပြီ');
                isUploading = false;
                localStorage.removeItem("activeJobId");
                currentJobId = null;
                setTimeout(() => window.location.reload(), 1000);
            } else {
                setTimeout(pollStatus, 3000); // 3 sec interval
            }
        } catch(e) {
            isUploading = false; showToast(e.message, 'error'); resetUI('remote');
        }
    }

    async function cancelRemote() { 
        if(currentJobId) {
            await fetch('/api/job/cancel', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ jobId: currentJobId })
            });
        }
        resetUI('remote'); 
        showToast("Upload Cancelled", 'error'); 
    }
</script>
`;

const Layout = (props: { children: any; title?: string; user?: User | null, csrfToken?: string, hideLoginLink?: boolean }) => {
    const isVip = props.user ? isVipActive(props.user) : false;
    return (
    <html lang="my">
        <head>
            <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>{props.title || "Gold Storage Cloud"}</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" />
            <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap" rel="stylesheet" />
            <style>{`
                body { font-family: 'Padauk', sans-serif; background-color: #050505; color: #e4e4e7; opacity: 1; transition: opacity 0.3s ease-in; }
                .glass { background: #121212; border: 1px solid #27272a; }
                .vip-card { background: linear-gradient(145deg, #18181b, #09090b); border: 1px solid #27272a; transition: 0.3s; }
                .vip-card:hover { border-color: #eab308; transform: translateY(-5px); }
                .custom-scroll::-webkit-scrollbar { width: 5px; }
                .custom-scroll::-webkit-scrollbar-track { background: #000; }
                .custom-scroll::-webkit-scrollbar-thumb { background: #333; border-radius: 5px; }
                .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.85); backdrop-filter: blur(4px); z-index: 100; display: flex; align-items: center; justify-content: center; }
                .modal-box { background: #18181b; border: 1px solid #eab308; border-radius: 16px; padding: 24px; width: 90%; max-width: 400px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); animation: modalPop 0.2s ease-out; }
                @keyframes modalPop { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }
            `}</style>
            <script dangerouslySetInnerHTML={{__html: `
                window.IS_VIP_USER = ${isVip}; 
                window.CSRF_TOKEN = "${props.csrfToken || ''}";
                window.STREAM_DOMAIN = "${STREAM_DOMAIN}";
                window.PROXY_URL = "${PROXY_URL}";
                window.R2_PUB_1 = "${R2_PUB_1}";
                window.R2_PUB_2 = "${R2_PUB_2}";
            `}} />
            <div dangerouslySetInnerHTML={{__html: ToastScript}} />
        </head>
        <body data-vip={isVip ? "true" : "false"}>
            <div id="toast-container" class="fixed top-20 right-5 z-[200] flex flex-col gap-3"></div>

            <nav class="fixed top-0 w-full z-50 glass border-b border-zinc-800 bg-black/80 backdrop-blur-md"><div class="max-w-5xl mx-auto px-4 py-3 flex justify-between items-center"><a href="/" class="text-xl font-black text-white italic tracking-tighter flex items-center gap-2"><i class="fa-solid fa-cube text-yellow-500"></i> <span class="bg-clip-text text-transparent bg-gradient-to-r from-yellow-400 to-yellow-600">GOLD STORAGE</span></a>
            {props.user ? (<div class="flex gap-3 items-center"><div class="hidden sm:flex flex-col items-end leading-tight"><span class="text-xs font-bold text-gray-300">{props.user.username}</span>{isVipActive(props.user) ? <span class="text-[9px] text-yellow-500 font-bold bg-yellow-500/10 px-1 rounded">VIP</span> : <span class="text-[9px] text-gray-500 font-bold bg-zinc-800 px-1 rounded">FREE</span>}</div>{props.user.username === ADMIN_USERNAME && <a href="/admin" class="w-8 h-8 flex items-center justify-center bg-purple-600 rounded-full hover:bg-purple-500 text-white"><i class="fa-solid fa-shield-halved text-xs"></i></a>}<a href="/logout" class="w-8 h-8 flex items-center justify-center bg-zinc-800 border border-zinc-700 rounded-full hover:bg-red-600/20 hover:text-red-500"><i class="fa-solid fa-power-off text-xs"></i></a></div>) : (
                !props.hideLoginLink && <a href="/login" class="text-xs bg-yellow-500 text-black px-4 py-2 rounded-full font-bold hover:bg-yellow-400 transition">ဝင်မည်</a>
            )}</div></nav>
            <main class="pt-20 pb-10 px-4 max-w-5xl mx-auto">{props.children}</main>
            <footer class="text-center py-8 border-t border-zinc-800 mt-10">
                <a href="https://t.me/iqowoq" target="_blank" class="text-zinc-500 hover:text-[#229ED9] transition flex items-center justify-center gap-2 text-sm font-bold"><i class="fa-brands fa-telegram text-xl"></i> Contact Admin</a>
                <p class="text-[10px] text-zinc-600 mt-2">© 2026 Gold Storage Cloud</p>
            </footer>
            
            <div id="vipModal" class="modal-overlay hidden"><div class="modal-box text-center relative overflow-hidden"><div class="absolute top-0 left-0 w-full h-1.5 bg-gradient-to-r from-yellow-600 to-yellow-400"></div><div class="w-16 h-16 bg-yellow-500/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-yellow-500/20"><i class="fa-solid fa-crown text-3xl text-yellow-500"></i></div><h3 class="text-xl font-black text-white mb-2 tracking-wide">VIP ONLY</h3><p class="text-sm text-gray-400 mb-6 leading-relaxed">Remote Upload စနစ်ကို အသုံးပြုရန်<br/><span class="text-yellow-500 font-bold">VIP Member</span> ဝင်ထားရန် လိုအပ်ပါသည်။</p><button onclick="closeModal('vipModal')" class="w-full bg-yellow-500 hover:bg-yellow-400 text-black font-bold py-3 rounded-xl transition shadow-lg shadow-yellow-500/20">နားလည်ပါပြီ</button></div></div>
            <div id="deleteModal" class="modal-overlay hidden"><div class="modal-box text-center"><div class="w-12 h-12 bg-red-900/30 text-red-500 rounded-full flex items-center justify-center mx-auto mb-4"><i class="fa-solid fa-trash text-xl"></i></div><h3 class="text-lg font-bold text-white mb-2">ဖိုင်ကို ဖျက်မည်လား?</h3><p class="text-sm text-gray-400 mb-6">ဤဖိုင်ကို အပြီးတိုင် ဖျက်သိမ်းပါမည်။ ပြန်ယူ၍ မရနိုင်ပါ။</p><div class="flex gap-3"><button onclick="closeModal('deleteModal')" class="flex-1 bg-zinc-800 hover:bg-zinc-700 text-white py-2.5 rounded-xl font-bold transition">မဖျက်တော့ပါ</button><button id="btnConfirmDelete" onclick="confirmDelete()" class="flex-1 bg-red-600 hover:bg-red-500 text-white py-2.5 rounded-xl font-bold transition">ဖျက်မည်</button></div></div></div>
            <div id="editModal" class="modal-overlay hidden"><div class="modal-box"><h3 class="text-lg font-bold text-white mb-4 flex items-center gap-2"><i class="fa-solid fa-clock text-yellow-500"></i> သက်တမ်း ပြင်ဆင်ရန်</h3><div class="mb-6"><label class="block text-xs font-bold text-gray-400 mb-2 uppercase">သက်တမ်းရွေးချယ်ပါ</label><div class="relative"><select id="editExpirySelect" class="w-full bg-black border border-zinc-700 text-white p-3 rounded-xl appearance-none outline-none focus:border-yellow-500 cursor-pointer"><option value="0">သက်တမ်းမဲ့ (Lifetime)</option><option value="1">၁ ရက်</option><option value="7">၁ ပတ်</option><option value="30">၁ လ</option><option value="365">၁ နှစ်</option></select><i class="fa-solid fa-chevron-down absolute right-4 top-4 text-gray-500 pointer-events-none"></i></div></div><div class="flex gap-3"><button onclick="closeModal('editModal')" class="flex-1 bg-zinc-800 hover:bg-zinc-700 text-white py-2.5 rounded-xl font-bold transition">မပြင်ပါ</button><button id="btnConfirmEdit" onclick="confirmEdit()" class="flex-1 bg-yellow-500 hover:bg-yellow-400 text-black py-2.5 rounded-xl font-bold transition">အတည်ပြုမည်</button></div></div></div>
            
            {/* Link Generator Modal */}
            <div id="linkModal" class="modal-overlay hidden">
                <div class="modal-box w-full max-w-lg relative">
                    <div class="flex justify-between items-center mb-4 border-b border-zinc-700 pb-3">
                        <h3 class="text-lg font-bold text-white flex items-center gap-2"><i class="fa-solid fa-link text-yellow-500"></i> Link Generator</h3>
                        <button onclick="closeModal('linkModal')" class="w-8 h-8 rounded-full bg-zinc-800 flex items-center justify-center text-gray-400 hover:text-white transition"><i class="fa-solid fa-xmark"></i></button>
                    </div>
                    <div class="mb-4">
                        <p class="text-[10px] text-zinc-500 uppercase font-bold mb-2">Generated Links (Server 1 & 2)</p>
                        <textarea id="allLinksArea" rows="10" class="w-full bg-black border border-zinc-700 rounded-xl p-3 text-[10px] text-green-400 font-mono focus:border-yellow-500 outline-none resize-none leading-relaxed" readonly onclick="this.select()"></textarea>
                    </div>
                    <button onclick="navigator.clipboard.writeText(document.getElementById('allLinksArea').value); showToast('Links Copied Successfully!'); closeModal('linkModal');" class="w-full bg-yellow-500 hover:bg-yellow-400 text-black font-bold py-3 rounded-xl transition shadow-lg flex items-center justify-center gap-2"><i class="fa-regular fa-copy"></i> Copy All Links</button>
                </div>
            </div>

            <div dangerouslySetInnerHTML={{__html: MainScript}} />
        </body>
    </html>
)};

// =======================
// ROUTES (Search & Pagination FIXED)
// =======================
app.get("/", async (c) => {
    const session = await getSessionUser(c);
    if (await isMaintenanceMode() && session?.user.username !== ADMIN_USERNAME) return c.html(<Layout hideLoginLink={true}><div class="text-center mt-32"><div class="w-20 h-20 bg-zinc-800 rounded-full flex items-center justify-center mx-auto mb-6"><i class="fa-solid fa-screwdriver-wrench text-4xl text-yellow-500"></i></div><h1 class="text-2xl font-bold text-white">Maintenance Mode</h1><p class="text-gray-400 mt-2">ဆာဗာ ပြုပြင်နေပါသဖြင့် ခေတ္တစောင့်ဆိုင်းပေးပါ။</p></div></Layout>);
    if(!session) return c.redirect("/login");
    const { user, csrfToken } = session;
    if(user.isBanned) return c.html(<Layout><div class="text-center mt-20 text-red-500 font-bold bg-zinc-900 p-10 rounded-xl border border-red-900"><i class="fa-solid fa-ban text-4xl mb-3"></i><br/>Your Account has been Banned.</div></Layout>);

    const filterType = c.req.query('type') || 'all';
    const searchQuery = c.req.query('q')?.toLowerCase();
    const cursor = c.req.query('cursor');
    const PAGE_SIZE = 20; 

    // Search or Filter
    const isSearching = (searchQuery && searchQuery.length > 0) || filterType !== 'all';
    const scanLimit = isSearching ? 1000 : (PAGE_SIZE + 1);

    const iter = kv.list<FileData>({ prefix: ["files", user.username] }, { reverse: true, limit: scanLimit, cursor: cursor });
    const files = []; 
    let nextCursor = "";
    
    for await (const res of iter) { 
        let match = true;
        if (searchQuery && !res.value.name.toLowerCase().includes(searchQuery)) match = false;
        if (filterType !== 'all' && res.value.type !== filterType) match = false;
        if (match) {
            files.push(res.value);
            if (files.length === PAGE_SIZE) nextCursor = iter.cursor; 
        }
    }
    let showNextButton = false;
    if (files.length > PAGE_SIZE) { showNextButton = true; files.pop(); }

    const totalGB = (user.usedStorage / 1024 / 1024 / 1024).toFixed(2);
    const currentPlan = PLANS[user.plan] || PLANS.free;
    const planLimit = currentPlan.limit;
    const displayLimit = (planLimit / 1024 / 1024 / 1024).toFixed(0) + " GB";
    const usedPercent = Math.min(100, (user.usedStorage / planLimit) * 100);
    const now = Date.now();
    const showWarning = (user.vipExpiry && user.vipExpiry < now);

    return c.html(<Layout user={user} csrfToken={csrfToken}>
        {maintenance && <div class="bg-yellow-900/50 border border-yellow-600/50 p-2 rounded-lg mb-4 text-center"><p class="text-yellow-500 font-bold text-xs"><i class="fa-solid fa-triangle-exclamation"></i> Maintenance Mode is ON (Admin Access)</p></div>}
        {showWarning && <div class="bg-red-900/50 border border-red-600/50 p-4 rounded-xl mb-6 flex items-start gap-3"><i class="fa-solid fa-triangle-exclamation text-red-500 text-xl mt-1"></i><div><h3 class="font-bold text-red-400 text-sm">သတိပေးချက်: VIP သက်တမ်းကုန်ဆုံးနေပါပြီ</h3><p class="text-xs text-gray-300 mt-1">၇-ရက်အတွင်း သက်တမ်းမတိုးပါက ဆာဗာမှ ဖိုင်များကို အလိုအလျောက် ဖျက်သိမ်းမည်ဖြစ်သည်။</p></div></div>}

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <div class="glass p-5 rounded-2xl relative overflow-hidden group">
                <div class="flex justify-between items-start">
                    <div><p class="text-xs text-zinc-500 uppercase font-bold mb-1">လက်ရှိအစီအစဉ်</p><p class={`text-2xl font-black ${isVipActive(user) ? 'text-yellow-500' : 'text-zinc-300'}`}>{currentPlan.name}</p></div>
                    <a href="/change-password" class="text-zinc-600 hover:text-white transition" title="Change Password"><i class="fa-solid fa-key"></i></a>
                </div>
                <div class="mt-4 bg-black/40 border border-zinc-700/50 rounded-xl p-3 flex items-center justify-between">
                    <div class="overflow-hidden mr-2"><p class="text-[9px] text-zinc-500 uppercase font-bold">သင့် Username</p><p class="text-lg font-bold text-white font-mono tracking-wider truncate">{user.username}</p></div>
                    <button onclick={`navigator.clipboard.writeText('${user.username}'); showToast('Username copied!');`} class="w-10 h-10 bg-zinc-800 hover:bg-zinc-700 rounded-lg flex items-center justify-center text-zinc-400 hover:text-white transition shadow-lg shrink-0"><i class="fa-regular fa-copy"></i></button>
                </div>
                <div class="mt-3">{user.vipExpiry ? (<p class={`text-[10px] font-mono px-2 py-1 rounded inline-block ${user.vipExpiry > now ? 'text-green-400 bg-green-900/20' : 'text-red-400 bg-red-900/20'}`}>{user.vipExpiry > now ? `VIP သက်တမ်း: ${formatDate(user.vipExpiry)}` : `သက်တမ်းကုန်ဆုံး: ${formatDate(user.vipExpiry)}`}</p>) : <p class="text-[10px] text-zinc-500"><i class="fa-solid fa-circle-info mr-1"></i> Free Version</p>}</div>
            </div>
            <div class="glass p-5 rounded-2xl relative">
                <div class="flex justify-between items-end mb-2"><div><p class="text-xs text-zinc-500 uppercase font-bold">သိုလှောင်ခန်း</p><p class="text-xl font-bold text-white">{totalGB} <span class="text-sm text-zinc-500">GB / {displayLimit}</span></p></div><span class="text-2xl font-black text-zinc-700">{usedPercent.toFixed(0)}%</span></div>
                <div class="w-full bg-zinc-800 rounded-full h-3 overflow-hidden"><div class={`h-full rounded-full ${isVipActive(user) ? 'bg-gradient-to-r from-yellow-600 to-yellow-400' : 'bg-zinc-600'}`} style={`width: ${usedPercent}%`}></div></div>
            </div>
            <div class="glass p-5 rounded-2xl flex flex-col justify-center gap-2">
                <div class="text-xs text-zinc-400 mb-1 font-bold uppercase">VIP အကျိုးခံစားခွင့်</div>
                <ul class="text-[10px] text-gray-400 space-y-1">
                    <li class="flex items-center gap-2"><i class="fa-solid fa-check text-yellow-500"></i> ဖိုင်သက်တမ်း စိတ်ကြိုက်ရွေးနိုင်</li>
                    <li class="flex items-center gap-2"><i class="fa-solid fa-check text-yellow-500"></i> VIP သက်တမ်းရှိသရွေ့ ဖိုင်မပျက်ပါ</li>
                    <li class="flex items-center gap-2"><i class="fa-solid fa-check text-yellow-500"></i> Remote URL Upload စနစ်</li>
                </ul>
            </div>
        </div>

        {!isVipActive(user) && (<div class="mb-10"><h2 class="text-white font-bold text-lg mb-4 flex items-center gap-2"><i class="fa-solid fa-crown text-yellow-500"></i> VIP အစီအစဉ်များ</h2><div class="grid grid-cols-2 md:grid-cols-5 gap-3">{[{gb:"50 GB", p:"3,000", c:"vip50"}, {gb:"100 GB", p:"5,000", c:"vip100"}, {gb:"300 GB", p:"12,000", c:"vip300"}, {gb:"500 GB", p:"22,000", c:"vip500"}, {gb:"1 TB", p:"40,000", c:"vip1t"}].map(p => (<div class="vip-card p-4 rounded-xl text-center relative overflow-hidden group"><div class="text-yellow-500 font-black text-lg">{p.gb}</div><div class="text-white text-sm font-bold my-1">{p.p} Ks <span class="text-[10px] text-gray-500">/mo</span></div><div class="text-[10px] text-gray-400">Remote Upload Access</div></div>))}</div><div class="text-center mt-6"><a href="https://t.me/iqowoq" target="_blank" class="inline-flex items-center gap-2 bg-[#229ED9] hover:bg-[#1e8bc0] text-white px-6 py-2.5 rounded-xl font-bold transition shadow-lg shadow-blue-500/20 group"><i class="fa-brands fa-telegram text-2xl group-hover:scale-110 transition-transform"></i><span>Admin ကို ဆက်သွယ်ရန်</span></a></div></div>)}

        {/* Upload Section */}
        <div class="glass p-6 rounded-2xl mb-8 border border-zinc-700/50 shadow-2xl relative overflow-hidden">
            <div class="flex flex-wrap gap-4 mb-6 border-b border-zinc-800 pb-4">
                <button id="btn-mode-local" onclick="switchUploadMode('local')" class="mode-btn px-4 py-2 text-xs font-bold rounded-lg bg-yellow-500 text-black transition flex items-center gap-2"><i class="fa-solid fa-upload"></i> ဖိုင်တင်မည်</button>
                <button id="btn-mode-remote" onclick="switchUploadMode('remote')" class="mode-btn px-4 py-2 text-xs font-bold rounded-lg bg-zinc-800 text-gray-400 hover:text-white transition flex items-center gap-2"><i class="fa-solid fa-globe"></i> လင့်ခ်ဖြင့်တင်မည် {isVipActive(user) ? "" : "(VIP)"}</button>
            </div>
            <div id="mode-local" class="upload-mode"><form id="uploadForm" onsubmit="uploadLocal(event)" class="space-y-5"><div class="grid grid-cols-1 md:grid-cols-2 gap-5"><div><label class="text-xs font-bold text-zinc-500 uppercase mb-2 block">ဖိုင်နာမည် ပေးရန်(Optional)</label><input name="customName" placeholder="ဖိုင်နာမည်..." class="w-full bg-black border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none text-white transition" /></div><div><label class="text-xs font-bold text-zinc-500 uppercase mb-2 block">ဖိုင် သက်တမ်း</label>{isVipActive(user) ? (<div class="relative"><select name="expiry" class="w-full bg-black border border-yellow-600/50 rounded-xl p-3 text-sm text-yellow-500 font-bold outline-none appearance-none cursor-pointer"><option value="0">သက်တမ်းမဲ့ (Lifetime)</option><option value="7">၁ ပတ်</option><option value="30">၁ လ</option></select><i class="fa-solid fa-chevron-down absolute right-4 top-4 text-yellow-500 pointer-events-none"></i></div>) : (<div class="relative"><input disabled value="၃၀ ရက် (Free Plan)" class="w-full bg-zinc-900 border border-zinc-700 text-gray-500 rounded-xl p-3 text-sm font-bold cursor-not-allowed" /><input type="hidden" name="expiry" value="30" /></div>)}</div></div><div class="grid grid-cols-2 gap-4"><label class="cursor-pointer relative"><input type="radio" name="server" value="1" class="peer sr-only" checked /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-blue-500 peer-checked:bg-blue-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-sm block text-gray-400 peer-checked:text-white">Server 1</span></div></label><label class="cursor-pointer relative"><input type="radio" name="server" value="2" class="peer sr-only" /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-yellow-500 peer-checked:bg-yellow-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-sm block text-gray-400 peer-checked:text-white">Server 2</span></div></label></div><div class="border-2 border-dashed border-zinc-800 rounded-2xl p-8 text-center hover:border-yellow-500/30 hover:bg-zinc-900 transition cursor-pointer group relative"><input type="file" id="fileInput" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"/><div class="space-y-2 pointer-events-none"><div class="w-12 h-12 bg-zinc-800 rounded-full flex items-center justify-center mx-auto text-zinc-400 group-hover:text-yellow-500 transition"><i id="uploadIcon" class="fa-solid fa-plus text-xl"></i></div><p id="fileNameDisplay" class="text-sm font-bold text-zinc-300 truncate px-4">ဖိုင်ရွေးချယ်ရန် နှိပ်ပါ</p><p class="text-[10px] text-zinc-500">{isVipActive(user) ? "Size: Unlimited" : "Size Limit: 50GB"}</p></div></div><div id="progressContainer" class="hidden"><div class="flex justify-between text-[10px] uppercase font-bold text-zinc-400 mb-1"><span>Uploading...</span><span id="progressText">0%</span></div><div class="flex items-center gap-3"><div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden"><div id="progressBar" class="bg-yellow-500 h-full rounded-full transition-all duration-300" style="width: 0%"></div></div><button type="button" id="cancelBtnLocal" onclick="cancelLocal()" class="bg-red-600 hover:bg-red-500 text-white w-6 h-6 rounded-full flex items-center justify-center transition flex-shrink-0" title="Cancel Upload"><i class="fa-solid fa-xmark text-xs"></i></button></div></div><button id="submitBtn" class="w-full bg-yellow-500 text-black font-bold py-3.5 rounded-xl shadow-lg hover:bg-yellow-400 transition active:scale-95">တင်မည်</button></form></div>
            <div id="mode-remote" class="upload-mode hidden"><form onsubmit="uploadRemote(event)" class="space-y-5"><div><label class="text-xs font-bold text-zinc-500 uppercase mb-2 block">Direct Video/File URL</label><input id="remoteUrl" type="url" placeholder="https://example.com/video.mp4" class="w-full bg-black border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none text-white" /></div><div class="grid grid-cols-1 md:grid-cols-2 gap-5"><div><label class="text-xs font-bold text-zinc-500 uppercase mb-2 block">ဖိုင်နာမည်</label><input id="remoteName" placeholder="video.mp4" class="w-full bg-black border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none text-white" /></div><div><label class="text-xs font-bold text-zinc-500 uppercase mb-2 block">သက်တမ်း</label><div class="relative"><select name="expiry_remote" class="w-full bg-black border border-yellow-600/50 rounded-xl p-3 text-sm text-yellow-500 font-bold outline-none appearance-none"><option value="0">သက်တမ်းမဲ့ (Lifetime)</option><option value="7">၁ ပတ်</option><option value="30">၁ လ</option></select><i class="fa-solid fa-chevron-down absolute right-4 top-4 text-yellow-500 pointer-events-none"></i></div></div></div><div class="grid grid-cols-3 gap-2"><label class="cursor-pointer relative"><input type="radio" name="server_remote" value="1" class="peer sr-only" checked /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-blue-500 peer-checked:bg-blue-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-xs block text-gray-400 peer-checked:text-white">Server 1</span></div></label><label class="cursor-pointer relative"><input type="radio" name="server_remote" value="2" class="peer sr-only" /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-yellow-500 peer-checked:bg-yellow-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-xs block text-gray-400 peer-checked:text-white">Server 2</span></div></label><label class="cursor-pointer relative"><input type="radio" name="server_remote" value="both" class="peer sr-only" /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-purple-500 peer-checked:bg-purple-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-xs block text-gray-400 peer-checked:text-white">Both (1+2)</span></div></label></div><div id="progressContainerRemote" class="hidden"><div class="flex justify-between text-[10px] uppercase font-bold text-zinc-400 mb-1"><span>Processing...</span><span id="progressTextRemote">0%</span></div><div class="flex items-center gap-3"><div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden"><div id="progressBarRemote" class="bg-yellow-500 h-full rounded-full transition-all duration-300" style="width: 0%"></div></div><button type="button" id="cancelBtnRemote" onclick="cancelRemote()" class="bg-red-600 hover:bg-red-500 text-white w-6 h-6 rounded-full flex items-center justify-center transition flex-shrink-0" title="Cancel Upload"><i class="fa-solid fa-xmark text-xs"></i></button></div></div><button id="remoteBtn" class="w-full bg-zinc-800 text-white border border-zinc-700 font-bold py-3.5 rounded-xl shadow-lg hover:bg-yellow-600 hover:text-black transition">Remote Upload (Max 15GB)</button></form></div>
        </div>

        <div class="flex flex-col md:flex-row md:items-center justify-between mb-4 gap-4">
            <h3 class="font-bold text-white text-sm uppercase tracking-wide"><i class="fa-solid fa-list-ul mr-2 text-zinc-500"></i> My Files</h3>
            <div class="flex gap-2 w-full md:w-auto">
                <form action="/" method="get" class="flex gap-2 w-full md:w-auto">
                    <input name="q" placeholder="Search + Enter..." class="bg-zinc-900 border border-zinc-700 text-white text-xs p-2 rounded-lg outline-none focus:border-yellow-500 w-full md:w-48" value={searchQuery || ''} />
                    <input type="hidden" name="type" value={filterType} />
                </form>
                <div class="flex bg-zinc-900 p-1 rounded-lg shrink-0">
                    <button onclick="switchTab('all')" class={`px-3 py-1 text-[10px] font-bold rounded-md transition ${filterType === 'all' ? 'bg-yellow-500 text-black' : 'text-gray-400'}`}>ALL</button>
                    <button onclick="switchTab('video')" class={`px-3 py-1 text-[10px] font-bold rounded-md transition ${filterType === 'video' ? 'bg-yellow-500 text-black' : 'text-gray-400'}`}>VID</button>
                    <button onclick="switchTab('image')" class={`px-3 py-1 text-[10px] font-bold rounded-md transition ${filterType === 'image' ? 'bg-yellow-500 text-black' : 'text-gray-400'}`}>IMG</button>
                </div>
            </div>
        </div>
        
        <div class="glass rounded-2xl overflow-hidden border border-zinc-700/50">
            <div class="max-h-[600px] overflow-y-auto custom-scroll p-2 space-y-2">
                {files.map(f => {
                    const viewLink = `${STREAM_DOMAIN}/d/${f.server}/${f.r2Key}`;
                    const downloadLink = `${STREAM_DOMAIN}/d/${f.server}/${f.r2Key}?dl=1`;
                    const fullFileName = f.r2Key.split('/').pop();
                    return (
                    <div class="file-item bg-zinc-900/50 hover:bg-zinc-800 p-3 rounded-xl border border-transparent hover:border-zinc-700 group transition">
                        <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
                            <div class="flex items-start gap-3 overflow-hidden w-full">
                                <div class={`w-10 h-10 rounded-lg flex items-center justify-center text-lg flex-shrink-0 mt-1 ${f.type === 'image' ? 'bg-yellow-500/10 text-yellow-500' : f.type === 'video' ? 'bg-blue-500/10 text-blue-500' : 'bg-zinc-700 text-zinc-400'}`}>
                                    <i class={`fa-solid ${f.type === 'image' ? 'fa-image' : f.type === 'video' ? 'fa-clapperboard' : 'fa-file'}`}></i>
                                </div>
                                <div class="min-w-0 w-full">
                                    <a href={viewLink} target="_blank" class="font-bold text-sm text-zinc-200 group-hover:text-yellow-500 transition hover:underline block truncate">{f.name}</a>
                                    <div class="flex flex-wrap items-center gap-2 text-[10px] text-zinc-500 font-mono mt-1">
                                        <span class="bg-black border border-zinc-800 px-1.5 py-0.5 rounded text-zinc-400">{f.size}</span>
                                        <span>{formatDate(f.uploadedAt)}</span>
                                        <span class="bg-zinc-800 px-1.5 py-0.5 rounded text-zinc-400">S{f.server}</span>
                                        {f.expiresAt > 0 ? (<span class="text-red-400 bg-red-900/10 px-1.5 py-0.5 rounded">Exp: {formatDate(f.expiresAt)}</span>) : (<span class="text-green-500 bg-green-900/10 px-1.5 py-0.5 rounded">Lifetime</span>)}
                                    </div>
                                </div>
                            </div>
                            <div class="flex gap-2 w-full md:w-auto justify-end border-t border-zinc-800 pt-2 md:pt-0 md:border-0">
                                {isVipActive(user) && <button onclick={`openEditModal('${f.id}')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-yellow-600 hover:text-black text-gray-300 rounded-lg transition" title="Edit"><i class="fa-solid fa-pen text-xs"></i></button>}
                                
                                <button onclick={`navigator.clipboard.writeText('${fullFileName}'); showToast('Full Filename Copied!')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-white hover:text-black text-gray-300 rounded-lg transition" title="Copy Full Name"><i class="fa-regular fa-file-lines text-xs"></i></button>
                                <button onclick={`openLinkModal('${f.r2Key}')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-purple-600 hover:text-white text-gray-300 rounded-lg transition" title="Get All Links"><i class="fa-solid fa-share-nodes text-xs"></i></button>
                                <button onclick={`navigator.clipboard.writeText('${viewLink}'); showToast('Link Copied!')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-white hover:text-black text-gray-300 rounded-lg transition" title="Copy Link"><i class="fa-solid fa-link text-xs"></i></button>
                                
                                <a href={viewLink} target="_blank" title="Play/View" class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-blue-600 text-white rounded-lg transition"><i class="fa-solid fa-eye text-xs"></i></a>
                                <a href={downloadLink} target="_blank" title="Download" class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-green-600 text-white rounded-lg transition"><i class="fa-solid fa-download text-xs"></i></a>
                                <button onclick={`openDeleteModal('${f.id}')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-red-600 text-white rounded-lg transition" title="Delete"><i class="fa-solid fa-trash text-xs"></i></button>
                            </div>
                        </div>
                    </div>
                )})}
                {files.length === 0 && <div class="text-center text-zinc-500 py-12"><p>ဖိုင်များ မရှိသေးပါ</p></div>}
                
                <div class="flex justify-center gap-3 pt-4 pb-2">
                    {cursor && (
                        <a href={`/?type=${filterType}&q=${searchQuery||''}`} class="inline-flex items-center gap-2 bg-zinc-800 border border-zinc-700 hover:bg-zinc-700 text-zinc-300 font-bold py-2 px-6 rounded-xl transition text-xs">
                            <i class="fa-solid fa-arrow-left"></i> နောက်ဆုံးဖိုင်များ
                        </a>
                    )}
                    {showNextButton && nextCursor && (
                        <a href={`/?type=${filterType}&q=${searchQuery||''}&cursor=${nextCursor}`} class="inline-flex items-center gap-2 bg-yellow-600 border border-yellow-600 hover:bg-yellow-500 text-black font-bold py-2 px-6 rounded-xl transition text-xs shadow-lg shadow-yellow-500/20">
                            နောက်ထပ် ({files.length} ခုပြထားသည်) <i class="fa-solid fa-arrow-right"></i>
                        </a>
                    )}
                </div>
            </div>
        </div>
    </Layout>);
});

// =======================
// ROUTES: BACKGROUND UPLOAD & JOBS
// =======================
app.post("/api/upload/remote", async (c) => {
    if(!await checkRateLimit(c, "upload_remote", 20)) return c.json({error: "Too many requests"}, 429);
    const session = await getSessionUser(c);
    if(!session || !isVipActive(session.user)) return c.json({error: "VIP Only"}, 403);
    const body = await c.req.json();
    if(body.csrf !== session.csrfToken) return c.json({error: "Invalid CSRF"}, 403);

    // Create Background Job
    const jobId = crypto.randomUUID();
    const job: UploadJob = {
        id: jobId,
        username: session.user.username,
        url: body.url,
        name: body.customName || "remote",
        server: body.server,
        expiry: body.expiry,
        status: "pending",
        progress: 0,
        createdAt: Date.now()
    };

    await kv.set(["jobs", jobId], job);
    
    // Trigger Worker (Async)
    processRemoteUpload(jobId);

    return c.json({ success: true, jobId: jobId });
});

app.get("/api/job/:id", async (c) => {
    const id = c.req.param("id");
    const res = await kv.get<UploadJob>(["jobs", id]);
    if(!res.value) return c.json({ error: "Job not found" }, 404);
    return c.json(res.value);
});

app.post("/api/job/cancel", async (c) => {
    const { jobId } = await c.req.json();
    const key = ["jobs", jobId];
    const res = await kv.get<UploadJob>(key);
    if(res.value) {
        res.value.status = "cancelled";
        await kv.set(key, res.value);
        return c.json({ success: true });
    }
    return c.json({ error: "Not found" });
});

Deno.serve(app.fetch);
