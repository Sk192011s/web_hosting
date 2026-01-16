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
    // In production, you might want to exit here. For now, we warn.
}

const app = new Hono();
app.use('*', secureHeaders());

const kv = await Deno.openKv();
const STREAM_DOMAIN = "https://goldstorage2.deno.dev";
const PROXY_URL = "https://proxy.avotc.tk";
const R2_PUB_1  = "https://pub-50fdd8fdb8474becb9427139f00206ad.r2.dev"; 
const R2_PUB_2  = "https://pub-45c2fb2299a2438ea38ae56d17f3078e.r2.dev";

const ADMIN_USERNAME = Deno.env.get("ADMIN_USERNAME") || "admin"; 
const SECRET_KEY = Deno.env.get("SECRET_SALT") || "change-this-secret-salt-immediately";
const MAX_REMOTE_SIZE = 15 * 1024 * 1024 * 1024; // 2 GB
const ALLOWED_EXTENSIONS = new Set(['jpg','jpeg','png','gif','webp','mp4','mkv','webm','mov','mp3','wav','zip','rar','7z','pdf','txt','doc','docx']);
const BLOCKED_EXTENSIONS = new Set(['exe','sh','php','svg','pl','py','js','html','htm','css','bat','cmd','msi','dll','apk']);

const PLANS = {
    free:  { limit: 50 * 1024 * 1024 * 1024, name: "Free Plan" },
    vip50: { limit: 50 * 1024 * 1024 * 1024, name: "50 GB VIP" },
    vip100:{ limit: 100 * 1024 * 1024 * 1024, name: "100 GB VIP" },
    vip300:{ limit: 300 * 1024 * 1024 * 1024, name: "300 GB VIP" },
    vip500:{ limit: 500 * 1024 * 1024 * 1024, name: "500 GB VIP" },
    vip1t: { limit: 1000 * 1024 * 1024 * 1024, name: "1 TB VIP" },
};

// =======================
// GLOBAL CONFIGURATION (Connection Pool)
// ဒီအပိုင်းက app.on အပေါ်မှာ ရှိကိုရှိရပါမယ်
// =======================
const s3Server1 = new S3Client({
  region: "auto",
  endpoint: `https://${Deno.env.get("R2_1_ACCOUNT_ID")}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: Deno.env.get("R2_1_ACCESS_KEY_ID")!, secretAccessKey: Deno.env.get("R2_1_SECRET_ACCESS_KEY")! },
});

const s3Server2 = new S3Client({
  region: "auto",
  endpoint: `https://${Deno.env.get("R2_2_ACCOUNT_ID")}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: Deno.env.get("R2_2_ACCESS_KEY_ID")!, secretAccessKey: Deno.env.get("R2_2_SECRET_ACCESS_KEY")! },
});
// Download အတွက် aws4fetch client များ (APK Size ပြဿနာဖြေရှင်းရန်)
const r2Fetcher1 = new AwsClient({
    accessKeyId: Deno.env.get("R2_1_ACCESS_KEY_ID")!,
    secretAccessKey: Deno.env.get("R2_1_SECRET_ACCESS_KEY")!,
    service: "s3", region: "auto",
});
const r2Fetcher2 = new AwsClient({
    accessKeyId: Deno.env.get("R2_2_ACCESS_KEY_ID")!,
    secretAccessKey: Deno.env.get("R2_2_SECRET_ACCESS_KEY")!,
    service: "s3", region: "auto",
});

// =======================
// DOWNLOAD ROUTE (STABLE PROXY HEAD)
// Fixes: "Flip-Flop" Size Issue & Bandwidth Saving
// =======================
app.on(['GET', 'HEAD'], "/d/:server/*", async (c) => {
    const server = c.req.param("server");
    const rawPath = c.req.path.split(`/d/${server}/`)[1];
    
    if (!rawPath) return c.text("Invalid Key", 400);
    
    const decodedKey = decodeURIComponent(rawPath);
    
    // Global Client ကို သုံးပါ (Connection မပြတ်အောင်)
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");

    try {
        // ဖိုင်အမျိုးအစား (Extension) ကြိုစစ်မယ်
        const ext = decodedKey.split('.').pop()?.toLowerCase() || "";
        let forceType = "application/octet-stream";
        if (ext === "mp4") forceType = "video/mp4";
        else if (ext === "mkv") forceType = "video/x-matroska";
        else if (ext === "webm") forceType = "video/webm";
        else if (ext === "jpg" || ext === "jpeg") forceType = "image/jpeg";
        else if (ext === "png") forceType = "image/png";

        // (A) HEAD REQUEST - Deno Proxy (Bandwidth မကုန်ပါ)
        // APK က Size မေးရင် Deno က R2 ကို ချက်ချင်းလှမ်းမေးပြီး ဖြေမယ်
        if (c.req.method === 'HEAD') {
            const headCmd = new HeadObjectCommand({ Bucket: bucket, Key: decodedKey });
            const headData = await client.send(headCmd);
            
            const headers = new Headers();
            // Size အမှန်ထည့်မယ်
            headers.set("Content-Length", String(headData.ContentLength));
            // Type အမှန် (Video) ထည့်မယ်
            headers.set("Content-Type", forceType !== "application/octet-stream" ? forceType : (headData.ContentType || forceType));
            headers.set("Accept-Ranges", "bytes");
            headers.set("Last-Modified", headData.LastModified?.toUTCString() || new Date().toUTCString());
            headers.set("ETag", headData.ETag || "");
            
            // Connection ကို ဖြတ်မချဖို့ APK ကို ပြောမယ်
            headers.set("Connection", "keep-alive");
            headers.set("Cache-Control", "public, max-age=0, must-revalidate");

            // 200 OK နဲ့ ပြန်မယ် (Redirect မလုပ်ဘူး)
            return new Response(null, { status: 200, headers: headers });
        }

        // (B) GET REQUEST - Redirect to R2
        // တကယ်ဒေါင်းမှ R2 ဆီ လွှတ်မယ်
        const isDownload = c.req.query('dl') === '1';
        const fileName = decodedKey.split('/').pop()?.replace(/-\d+(\.[a-zA-Z0-9]+)?$/, "$1") || "file";
        const encodedFileName = encodeURIComponent(fileName);
        
        const disposition = `${isDownload ? "attachment" : "inline"}; filename="${encodedFileName}"; filename*=UTF-8''${encodedFileName}`;

        const command = new GetObjectCommand({ 
            Bucket: bucket, 
            Key: decodedKey, 
            ResponseContentDisposition: disposition,
            ResponseContentType: forceType // Signed URL မှာ Type အမှန်ထည့်မယ်
        });

        const url = await getSignedUrl(client, command, { expiresIn: 10800 }); // 3 Hours
        
        c.header("Cache-Control", "no-cache, no-store, must-revalidate");
        return c.redirect(url, 302);

    } catch (e) {
        return c.text("File Not Found", 404);
    }
});

// =======================
// 2. TYPES & HELPERS
// =======================
interface User { 
    username: string; passwordHash: string; plan: keyof typeof PLANS; isVip: boolean; vipExpiry?: number; usedStorage: number; createdAt: number; isBanned?: boolean;
}
interface Session { username: string; expires: number; csrfToken: string; }
interface FileData { id: string; name: string; sizeBytes: number; size: string; server: "1" | "2"; r2Key: string; uploadedAt: number; expiresAt: number; type: "image" | "video" | "other"; isVipFile: boolean; }
interface SystemConfig { maintenance: boolean; }

// --- Security & Utils ---
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

// --- SSRF Protection Helper ---
async function validateRemoteUrl(urlStr: string): Promise<void> {
    try {
        const url = new URL(urlStr);
        if (!['http:', 'https:'].includes(url.protocol)) throw new Error("Invalid protocol");
        const host = url.hostname;
        
        // Basic check for localhost/private IPs in string
        if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]') throw new Error("Localhost denied");
        if (host.startsWith('192.168.') || host.startsWith('10.') || host.match(/^172\.(1[6-9]|2\d|3[0-1])\./)) throw new Error("Private IP denied");

        // Advanced: DNS Resolution check (Prevent DNS Rebinding)
        // Note: Deno.resolveDns requires permission. If failing on some envs, catch error.
        try {
            const ips = await Deno.resolveDns(host, "A");
            for (const ip of ips) {
                if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("0.")) {
                    throw new Error("Resolved to Private IP");
                }
            }
        } catch (e) {
            // If DNS resolution fails or is not supported, we rely on string check (acceptable for basic usage)
            if(e.message === "Resolved to Private IP") throw e;
        }
    } catch (e) { throw new Error("Invalid or Blocked URL: " + e.message); }
}

// --- Session Management ---
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
   const newExpires = Date.now() + (7 * 24 * 60 * 60 * 1000);
kv.set(["sessions", sessionId], { ...res.value, expires: newExpires }, { expireIn: 7 * 24 * 60 * 60 * 1000 });
    
    const uRes = await kv.get<User>(["users", res.value.username]);
    if (!uRes.value) return null;
    
    // Auto-fix plan if missing
    const user = uRes.value;
    if (!user.plan || !PLANS[user.plan]) { user.plan = user.isVip ? 'vip50' : 'free'; await kv.set(["users", user.username], user); }
    return { user, csrfToken: res.value.csrfToken };
}

// --- Validations ---
function validateFileName(name: string): { valid: boolean, error?: string, safeName?: string, ext?: string } {
    const ext = name.split('.').pop()?.toLowerCase() || '';
    if (BLOCKED_EXTENSIONS.has(ext)) return { valid: false, error: "Security Restriction: This file type is not allowed." };
    const safeName = name.replace(/[^a-zA-Z0-9.\-_\u1000-\u109F]/g, "_");
    return { valid: true, safeName, ext };
}

function isVipActive(user: User): boolean { if (user.plan === 'free') return false; return user.vipExpiry ? user.vipExpiry > Date.now() : false; }
function formatDate(ts: number) { return new Date(ts).toLocaleDateString('my-MM', { day: 'numeric', month: 'short', year: 'numeric' }); }
// မူရင်း mimeToExt အစား ဒီ function နဲ့ လဲလိုက်ပါ
function mimeToExt(mime: string): string { 
    if (!mime) return 'bin';
    const m: any = {
        'video/mp4':'mp4','video/webm':'webm','video/x-matroska':'mkv',
        'image/jpeg':'jpg','image/png':'png', 'image/gif':'gif', 'image/webp':'webp',
        'text/plain':'txt', 'application/pdf':'pdf', // txt နဲ့ pdf ထပ်ဖြည့်ထားပါတယ်
        'application/zip':'zip', 'application/x-zip-compressed':'zip',
        'application/vnd.android.package-archive':'apk'
    }; 
    return m[mime.split(';')[0]] || 'bin'; 
}

// =======================
// 3. FRONTEND COMPONENTS
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
    window.onbeforeunload = function() { if (isUploading) return "Upload in progress. Leave?"; };
    document.body.style.opacity = '1';

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
    // --- Link Generator Modal Function (FIXED) ---
    function openLinkModal(r2Key) {
        const modal = document.getElementById('linkModal');
        const area = document.getElementById('allLinksArea');
        if(!modal || !area) return;
        
        modal.classList.remove('hidden');
        
        // window ကနေ Variable တွေ ယူသုံးပါမယ် (Error မတက်အောင်လို့ပါ)
        const domain = window.STREAM_DOMAIN; 
        const proxy = window.PROXY_URL;
        const pub1 = window.R2_PUB_1;
        const pub2 = window.R2_PUB_2;

        // Link များ တည်ဆောက်ခြင်း
        const s1_dl    = domain + "/d/1/" + r2Key + "?dl=1";
        const s1_raw   = pub1 + "/" + r2Key;
        const s1_proxy = proxy + "/" + pub1 + "/" + r2Key;

        const s2_dl    = domain + "/d/2/" + r2Key + "?dl=1";
        const s2_raw   = pub2 + "/" + r2Key;
        const s2_proxy = proxy + "/" + pub2 + "/" + r2Key;

        // Textarea ထဲ ထည့်ခြင်း
        const text = 
            "🛡️ [ PROXY LINKS ]\\n" +
            s1_proxy + "\\n" +
            s2_proxy + "\\n\\n" +

            "📥 [ DIRECT LINKS ]\\n" +
            s1_dl + "\\n" +
            s2_dl + "\\n\\n" +

            "🌐 [ PUBLIC LINKS ]\\n" +
            s1_raw + "\\n" +
            s2_raw;

        area.value = text;
    }

    // --- CLIENT SIDE SECURITY CHECKS ---
    async function checkFileSignature(file) {
        const slice = file.slice(0, 4);
        const buffer = await slice.arrayBuffer();
        const uint = new Uint8Array(buffer);
        let bytes = [];
        uint.forEach((byte) => bytes.push(byte.toString(16)));
        const hex = bytes.join("").toUpperCase();

        // Basic Magic Numbers Check
        // Executables (EXE, DLL) usually start with 4D 5A
        if (hex.startsWith('4D5A')) return false; 
        
        // Script tags check for HTML/PHP (simple check)
        // If it's a text file, we might want to scan for <?php or <script
        // For this demo, blocking '4D5A' covers most dangerous EXE disguises.
        return true;
    }

    // --- Upload Handlers ---
    let activeXHR = null;
    function cancelLocal() { if(activeXHR) { activeXHR.abort(); activeXHR = null; isUploading = false; resetUI('local'); showToast("Upload Cancelled", 'error'); } }
    function resetUI(mode) {
         if(mode === 'local') {
            document.getElementById('progressContainer').classList.add('hidden');
            setLoading('submitBtn', false); document.getElementById('progressBar').style.width = '0%';
         } else {
            document.getElementById('progressContainerRemote').classList.add('hidden');
            setLoading('remoteBtn', false); document.getElementById('progressBarRemote').style.width = '0%';
         }
    }

    document.getElementById('fileInput')?.addEventListener('change', function() {
        if (this.files && this.files.length > 0) {
            const f = this.files[0];
            document.getElementById('fileNameDisplay').innerText = f.name + " (" + (f.size/1024/1024).toFixed(1) + " MB)";
            document.getElementById('fileNameDisplay').classList.add('text-yellow-500', 'font-bold');
        }
    });

    async function uploadLocal(event) {
        event.preventDefault();
        const fileInput = document.getElementById('fileInput');
        const formData = new FormData(document.getElementById('uploadForm'));
        if(fileInput.files.length === 0) { showToast("ကျေးဇူးပြု၍ ဖိုင်ရွေးပါ", 'error'); return; }
        
        const file = fileInput.files[0];
        
        // 1. Client-Side Security Check
        const isSafe = await checkFileSignature(file);
        if(!isSafe) { showToast("Security Warning: မသင်္ကာဖွယ် ဖိုင်အမျိုးအစား (Blocked)", 'error'); return; }

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

    let activeRemoteController = null;
    function cancelRemote() { if(activeRemoteController) { activeRemoteController.abort(); activeRemoteController = null; isUploading = false; resetUI('remote'); showToast("Remote Upload Cancelled", 'error'); } }

    async function uploadRemote(event) {
        event.preventDefault();
        const urlInput = document.getElementById('remoteUrl');
        if(!urlInput.value) { showToast("URL ထည့်ပေးပါ", 'error'); return; }
        
        isUploading = true;
        setLoading('remoteBtn', true, 'ချိတ်ဆက်နေသည်...');
        document.getElementById('progressContainerRemote').classList.remove('hidden');
        document.getElementById('cancelBtnRemote').classList.remove('hidden');

        activeRemoteController = new AbortController();

        try {
            const response = await fetch('/api/upload/remote', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                signal: activeRemoteController.signal,
                body: JSON.stringify({
                    url: urlInput.value,
                    customName: document.getElementById('remoteName').value,
                    server: document.querySelector('input[name="server_remote"]:checked').value,
                    expiry: document.querySelector('select[name="expiry_remote"]').value,
                    csrf: window.CSRF_TOKEN
                })
            });

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';
            
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\\n');
                buffer = lines.pop(); 
                
                for (const line of lines) {
                    if (!line.trim()) continue;
                    try {
                        const msg = JSON.parse(line);
                        if (msg.error) throw new Error(msg.error);
                        if (msg.progress) {
                             if (msg.progress < 99) document.getElementById('remoteBtn').innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Downloading & Uploading...';
                             else document.getElementById('remoteBtn').innerHTML = '<i class="fa-solid fa-floppy-disk fa-spin"></i> Finalizing...';
                             document.getElementById('progressBarRemote').style.width = msg.progress + "%";
                             document.getElementById('progressTextRemote').innerText = msg.progress + "%";
                        }
                        if (msg.done) {
                            document.getElementById('progressBarRemote').classList.add('bg-green-500');
                            document.getElementById('cancelBtnRemote').classList.add('hidden');
                            showToast('Remote Upload အောင်မြင်သည်');
                            isUploading = false;
                            setTimeout(() => window.location.reload(), 1000);
                        }
                    } catch (e) { throw e; }
                }
            }
        } catch (e) { 
            if(e.name === 'AbortError') return;
            isUploading = false; showToast(e.message, 'error'); resetUI('remote');
        }
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
                body { font-family: 'Padauk', sans-serif; background-color: #050505; color: #e4e4e7; opacity: 0; transition: opacity 0.3s ease-in; }
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
            {/* 👇 ဒီ Script လိုင်းကို အစားထိုးလိုက်ပါ 👇 */}
            <script dangerouslySetInnerHTML={{__html: `
                window.IS_VIP_USER = ${isVip}; 
                window.CSRF_TOKEN = "${props.csrfToken || ''}";
                
                // Server Configs to Client Configs
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
            {/* ... editModal ပြီးတဲ့နေရာ ... */}
            
            <div id="linkModal" class="modal-overlay hidden">
                <div class="modal-box w-full max-w-lg">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-bold text-white"><i class="fa-solid fa-link text-yellow-500"></i> All Links Generator</h3>
                        <button onclick="closeModal('linkModal')" class="text-gray-500 hover:text-white"><i class="fa-solid fa-xmark text-xl"></i></button>
                    </div>
                    
                    <p class="text-xs text-gray-400 mb-2">Server 1 & 2 (Direct + Public + Proxy) Links:</p>
                    <textarea id="allLinksArea" rows="8" class="w-full bg-black border border-zinc-700 rounded-xl p-3 text-[10px] text-green-400 font-mono focus:border-yellow-500 outline-none" readonly></textarea>
                    
                    <div class="mt-4">
                        <button onclick="navigator.clipboard.writeText(document.getElementById('allLinksArea').value); showToast('All Links Copied!');" class="w-full bg-yellow-600 hover:bg-yellow-500 text-black font-bold py-3 rounded-xl transition">
                            <i class="fa-regular fa-copy"></i> Copy All Links
                        </button>
                    </div>
                </div>
            </div>

            {/* ... dangerouslySetInnerHTML မတိုင်ခင် ... */}

            <div dangerouslySetInnerHTML={{__html: MainScript}} />
        </body>
    </html>
)};

// =======================
// MAIN ROUTE (Pagination FIXED: Next + Back Buttons)
// =======================
app.get("/", async (c) => {
    const session = await getSessionUser(c);
    const maintenance = await isMaintenanceMode();
    
    if (maintenance && session?.user.username !== ADMIN_USERNAME) {
        return c.html(<Layout hideLoginLink={true}><div class="text-center mt-32"><div class="w-20 h-20 bg-zinc-800 rounded-full flex items-center justify-center mx-auto mb-6"><i class="fa-solid fa-screwdriver-wrench text-4xl text-yellow-500"></i></div><h1 class="text-2xl font-bold text-white">Maintenance Mode</h1><p class="text-gray-400 mt-2">ဆာဗာ ပြုပြင်နေပါသဖြင့် ခေတ္တစောင့်ဆိုင်းပေးပါ။</p></div></Layout>);
    }

    if(!session) return c.redirect("/login");
    const { user, csrfToken } = session;
    
    if(user.isBanned) return c.html(<Layout><div class="text-center mt-20 text-red-500 font-bold bg-zinc-900 p-10 rounded-xl border border-red-900"><i class="fa-solid fa-ban text-4xl mb-3"></i><br/>Your Account has been Banned.</div></Layout>);

    const filterType = c.req.query('type') || 'all';
    const searchQuery = c.req.query('q')?.toLowerCase();
    const cursor = c.req.query('cursor'); // လက်ရှိရောက်နေတဲ့ စာမျက်နှာအမှတ်အသား
    
    const PAGE_SIZE = 20; 

    const iter = kv.list<FileData>({ prefix: ["files", user.username] }, { reverse: true, limit: PAGE_SIZE + 1, cursor: cursor });
    
    const files = []; 
    let nextCursor = "";
    
    for await (const res of iter) { 
        let match = true;
        if (searchQuery && !res.value.name.toLowerCase().includes(searchQuery)) match = false;
        if (filterType !== 'all' && res.value.type !== filterType) match = false;

        if (match) {
            files.push(res.value);
            if (files.length === PAGE_SIZE) {
                nextCursor = iter.cursor; 
            }
        }
    }

    let showNextButton = false;
    if (files.length > PAGE_SIZE) {
        showNextButton = true;
        files.pop(); 
    }

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

        {!isVipActive(user) && (
        <div class="mb-10">
            <h2 class="text-white font-bold text-lg mb-4 flex items-center gap-2"><i class="fa-solid fa-crown text-yellow-500"></i> VIP အစီအစဉ်များ</h2>
            <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
                {[{gb:"50 GB", p:"3,000", c:"vip50"}, {gb:"100 GB", p:"5,000", c:"vip100"}, {gb:"300 GB", p:"12,000", c:"vip300"}, {gb:"500 GB", p:"22,000", c:"vip500"}, {gb:"1 TB", p:"40,000", c:"vip1t"}].map(p => (
                    <div class="vip-card p-4 rounded-xl text-center relative overflow-hidden group">
                        <div class="text-yellow-500 font-black text-lg">{p.gb}</div>
                        <div class="text-white text-sm font-bold my-1">{p.p} Ks <span class="text-[10px] text-gray-500">/mo</span></div>
                        <div class="text-[10px] text-gray-400">Remote Upload Access</div>
                    </div>
                ))}
            </div>
            <div class="text-center mt-6">
                <a href="https://t.me/iqowoq" target="_blank" class="inline-flex items-center gap-2 bg-[#229ED9] hover:bg-[#1e8bc0] text-white px-6 py-2.5 rounded-xl font-bold transition shadow-lg shadow-blue-500/20 group">
                    <i class="fa-brands fa-telegram text-2xl group-hover:scale-110 transition-transform"></i><span>Admin ကို ဆက်သွယ်ရန်</span>
                </a>
            </div>
        </div>
        )}

        <div class="glass p-6 rounded-2xl mb-8 border border-zinc-700/50 shadow-2xl relative overflow-hidden">
            <div class="flex flex-wrap gap-4 mb-6 border-b border-zinc-800 pb-4">
                <button id="btn-mode-local" onclick="switchUploadMode('local')" class="mode-btn px-4 py-2 text-xs font-bold rounded-lg bg-yellow-500 text-black transition flex items-center gap-2"><i class="fa-solid fa-upload"></i> ဖိုင်တင်မည်</button>
                <button id="btn-mode-remote" onclick="switchUploadMode('remote')" class="mode-btn px-4 py-2 text-xs font-bold rounded-lg bg-zinc-800 text-gray-400 hover:text-white transition flex items-center gap-2"><i class="fa-solid fa-globe"></i> လင့်ခ်ဖြင့်တင်မည် {isVipActive(user) ? "" : "(VIP)"}</button>
            </div>

            <div id="mode-local" class="upload-mode">
                <form id="uploadForm" onsubmit="uploadLocal(event)" class="space-y-5">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                        <div><label class="text-xs font-bold text-zinc-500 uppercase mb-2 block">ဖိုင်နာမည် ပေးရန်(Optional)</label><input name="customName" placeholder="ဖိုင်နာမည်..." class="w-full bg-black border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none text-white transition" /></div>
                        <div><label class="text-xs font-bold text-zinc-500 uppercase mb-2 block">ဖိုင် သက်တမ်း</label>{isVipActive(user) ? (<div class="relative"><select name="expiry" class="w-full bg-black border border-yellow-600/50 rounded-xl p-3 text-sm text-yellow-500 font-bold outline-none appearance-none cursor-pointer"><option value="0">သက်တမ်းမဲ့ (Lifetime)</option><option value="7">၁ ပတ်</option><option value="30">၁ လ</option></select><i class="fa-solid fa-chevron-down absolute right-4 top-4 text-yellow-500 pointer-events-none"></i></div>) : (<div class="relative"><input disabled value="၃၀ ရက် (Free Plan)" class="w-full bg-zinc-900 border border-zinc-700 text-gray-500 rounded-xl p-3 text-sm font-bold cursor-not-allowed" /><input type="hidden" name="expiry" value="30" /></div>)}</div>
                    </div>
                    <div class="grid grid-cols-2 gap-4"><label class="cursor-pointer relative"><input type="radio" name="server" value="1" class="peer sr-only" checked /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-blue-500 peer-checked:bg-blue-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-sm block text-gray-400 peer-checked:text-white">Server 1</span></div></label><label class="cursor-pointer relative"><input type="radio" name="server" value="2" class="peer sr-only" /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-yellow-500 peer-checked:bg-yellow-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-sm block text-gray-400 peer-checked:text-white">Server 2</span></div></label></div>
                    <div class="border-2 border-dashed border-zinc-800 rounded-2xl p-8 text-center hover:border-yellow-500/30 hover:bg-zinc-900 transition cursor-pointer group relative">
                        <input type="file" id="fileInput" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"/>
                        <div class="space-y-2 pointer-events-none"><div class="w-12 h-12 bg-zinc-800 rounded-full flex items-center justify-center mx-auto text-zinc-400 group-hover:text-yellow-500 transition"><i id="uploadIcon" class="fa-solid fa-plus text-xl"></i></div><p id="fileNameDisplay" class="text-sm font-bold text-zinc-300 truncate px-4">ဖိုင်ရွေးချယ်ရန် နှိပ်ပါ</p><p class="text-[10px] text-zinc-500">{isVipActive(user) ? "Size: Unlimited" : "Size Limit: 50GB"}</p></div>
                    </div>
                    <div id="progressContainer" class="hidden"><div class="flex justify-between text-[10px] uppercase font-bold text-zinc-400 mb-1"><span>Uploading...</span><span id="progressText">0%</span></div><div class="flex items-center gap-3"><div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden"><div id="progressBar" class="bg-yellow-500 h-full rounded-full transition-all duration-300" style="width: 0%"></div></div><button type="button" id="cancelBtnLocal" onclick="cancelLocal()" class="bg-red-600 hover:bg-red-500 text-white w-6 h-6 rounded-full flex items-center justify-center transition flex-shrink-0" title="Cancel Upload"><i class="fa-solid fa-xmark text-xs"></i></button></div></div>
                    <button id="submitBtn" class="w-full bg-yellow-500 text-black font-bold py-3.5 rounded-xl shadow-lg hover:bg-yellow-400 transition active:scale-95">တင်မည်</button>
                </form>
            </div>

            <div id="mode-remote" class="upload-mode hidden">
                <form onsubmit="uploadRemote(event)" class="space-y-5">
                    <div><label class="text-xs font-bold text-zinc-500 uppercase mb-2 block">Direct Video/File URL</label><input id="remoteUrl" type="url" placeholder="https://example.com/video.mp4" class="w-full bg-black border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none text-white" /></div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                        <div><label class="text-xs font-bold text-zinc-500 uppercase mb-2 block">ဖိုင်နာမည်</label><input id="remoteName" placeholder="video.mp4" class="w-full bg-black border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none text-white" /></div>
                        <div><label class="text-xs font-bold text-zinc-500 uppercase mb-2 block">သက်တမ်း</label><div class="relative"><select name="expiry_remote" class="w-full bg-black border border-yellow-600/50 rounded-xl p-3 text-sm text-yellow-500 font-bold outline-none appearance-none"><option value="0">သက်တမ်းမဲ့ (Lifetime)</option><option value="7">၁ ပတ်</option><option value="30">၁ လ</option></select><i class="fa-solid fa-chevron-down absolute right-4 top-4 text-yellow-500 pointer-events-none"></i></div></div>
                    </div>
                    <div class="grid grid-cols-3 gap-2">
                        <label class="cursor-pointer relative"><input type="radio" name="server_remote" value="1" class="peer sr-only" checked /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-blue-500 peer-checked:bg-blue-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-xs block text-gray-400 peer-checked:text-white">Server 1</span></div></label>
                        <label class="cursor-pointer relative"><input type="radio" name="server_remote" value="2" class="peer sr-only" /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-yellow-500 peer-checked:bg-yellow-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-xs block text-gray-400 peer-checked:text-white">Server 2</span></div></label>
                        <label class="cursor-pointer relative"><input type="radio" name="server_remote" value="both" class="peer sr-only" /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-purple-500 peer-checked:bg-purple-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-xs block text-gray-400 peer-checked:text-white">Both (1+2)</span></div></label>
                    </div>
                    <div id="progressContainerRemote" class="hidden"><div class="flex justify-between text-[10px] uppercase font-bold text-zinc-400 mb-1"><span>Processing...</span><span id="progressTextRemote">0%</span></div><div class="flex items-center gap-3"><div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden"><div id="progressBarRemote" class="bg-yellow-500 h-full rounded-full transition-all duration-300" style="width: 0%"></div></div><button type="button" id="cancelBtnRemote" onclick="cancelRemote()" class="bg-red-600 hover:bg-red-500 text-white w-6 h-6 rounded-full flex items-center justify-center transition flex-shrink-0" title="Cancel Upload"><i class="fa-solid fa-xmark text-xs"></i></button></div></div>
                    <button id="remoteBtn" class="w-full bg-zinc-800 text-white border border-zinc-700 font-bold py-3.5 rounded-xl shadow-lg hover:bg-yellow-600 hover:text-black transition">Remote Upload (Max 15GB)</button>
                </form>
            </div>
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
            // အစ်ကို့ရဲ့ Stream Domain Logic အတိုင်း ထားပေးထားပါတယ်
            const viewLink = `${STREAM_DOMAIN}/d/${f.server}/${f.r2Key}`;
            const downloadLink = `${STREAM_DOMAIN}/d/${f.server}/${f.r2Key}?dl=1`;
            
            return (
            <div class="file-item bg-zinc-900/50 hover:bg-zinc-800 p-3 rounded-xl border border-transparent hover:border-zinc-700 group transition">
                <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
                    {/* File Icon & Info */}
                    <div class="flex items-start gap-3 overflow-hidden w-full">
                        <div class={`w-10 h-10 rounded-lg flex items-center justify-center text-lg flex-shrink-0 mt-1 ${f.type === 'image' ? 'bg-yellow-500/10 text-yellow-500' : f.type === 'video' ? 'bg-blue-500/10 text-blue-500' : 'bg-zinc-700 text-zinc-400'}`}>
                            <i class={`fa-solid ${f.type === 'image' ? 'fa-image' : f.type === 'video' ? 'fa-clapperboard' : 'fa-file'}`}></i>
                        </div>
                        <div class="min-w-0 w-full">
                            {/* နာမည်ကိုနှိပ်ရင် Play မယ် */}
                            <a href={viewLink} target="_blank" class="font-bold text-sm text-zinc-200 group-hover:text-yellow-500 transition hover:underline block truncate">{f.name}</a>
                            <div class="flex flex-wrap items-center gap-2 text-[10px] text-zinc-500 font-mono mt-1">
                                <span class="bg-black border border-zinc-800 px-1.5 py-0.5 rounded text-zinc-400">{f.size}</span>
                                <span>{formatDate(f.uploadedAt)}</span>
                                <span class="bg-zinc-800 px-1.5 py-0.5 rounded text-zinc-400">S{f.server}</span>
                                {f.expiresAt > 0 ? (<span class="text-red-400 bg-red-900/10 px-1.5 py-0.5 rounded">Exp: {formatDate(f.expiresAt)}</span>) : (<span class="text-green-500 bg-green-900/10 px-1.5 py-0.5 rounded">Lifetime</span>)}
                            </div>
                        </div>
                    </div>

                    {/* Action Buttons */}
                    <div class="flex gap-2 w-full md:w-auto justify-end border-t border-zinc-800 pt-2 md:pt-0 md:border-0">
                        {isVipActive(user) && <button onclick={`openEditModal('${f.id}')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-yellow-600 hover:text-black text-gray-300 rounded-lg transition" title="Edit"><i class="fa-solid fa-pen text-xs"></i></button>}
                        
                        {/* 🔥 ဖိုင်နာမည် Copy ယူရန် ခလုတ် (အသစ်) 🔥 */}
                        <button onclick={`navigator.clipboard.writeText('${f.name}'); showToast('Filename Copied!')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-white hover:text-black text-gray-300 rounded-lg transition" title="Copy Filename"><i class="fa-regular fa-file-lines text-xs"></i></button>
                        <button onclick={`openLinkModal('${f.r2Key}')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-purple-600 hover:text-white text-gray-300 rounded-lg transition" title="Get All Links">
    <i class="fa-solid fa-share-nodes text-xs"></i>
</button>
                        
                        {/* Link Copy (Icon ပြောင်းထားသည်) */}
                        <button onclick={`navigator.clipboard.writeText('${viewLink}'); showToast('Link Copied!')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-white hover:text-black text-gray-300 rounded-lg transition" title="Copy Link"><i class="fa-solid fa-link text-xs"></i></button>
                        
                        <a href={viewLink} target="_blank" title="Play/View" class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-blue-600 text-white rounded-lg transition"><i class="fa-solid fa-eye text-xs"></i></a>
                        <a href={downloadLink} target="_blank" title="Download" class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-green-600 text-white rounded-lg transition"><i class="fa-solid fa-download text-xs"></i></a>
                        <button onclick={`openDeleteModal('${f.id}')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 hover:bg-red-600 text-white rounded-lg transition" title="Delete"><i class="fa-solid fa-trash text-xs"></i></button>
                    </div>
                </div>
            </div>
        )})}
        {files.length === 0 && <div class="text-center text-zinc-500 py-12"><p>ဖိုင်များ မရှိသေးပါ</p></div>}
        
        {/* Pagination Buttons (ရှိပြီးသားအတိုင်းထားပါ) */}
        {/* ... */}
                
                {/* Pagination Controls */}
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
// 5. API ROUTES
// =======================
app.post("/api/upload/presign", async (c) => {
    if(!await checkRateLimit(c, "upload_init", 10)) return c.json({error: "Too many requests"}, 429);
    const session = await getSessionUser(c); if(!session) return c.json({error: "Login required"}, 401);
    const { name, size, server, type, customName, csrf } = await c.req.json();
    if(csrf !== session.csrfToken) return c.json({error: "Invalid CSRF"}, 403);
    
    if (await isMaintenanceMode() && session.user.username !== ADMIN_USERNAME) return c.json({ error: "Maintenance Mode On" }, 503);

    const limitBytes = PLANS[session.user.plan]?.limit || PLANS.free.limit;
    if (session.user.usedStorage + size > limitBytes) return c.json({ error: "Storage Full" }, 400);

    const nameCheck = validateFileName(name);
    if (!nameCheck.valid) return c.json({ error: nameCheck.error }, 400);

    let finalName = name;
    if (customName) { 
        const cleanCustom = customName.replace(/[<>:"/\\|?*]/g, "");
        finalName = cleanCustom.endsWith('.' + nameCheck.ext) ? cleanCustom : cleanCustom + '.' + nameCheck.ext; 
    }
    
    const safeName = finalName.replace(/[^a-zA-Z0-9.\-_\u1000-\u109F]/g, "_");
    const parts = safeName.lastIndexOf('.');
    const nameBase = parts !== -1 ? safeName.substring(0, parts) : safeName;
    const ext = parts !== -1 ? safeName.substring(parts) : '';
    const r2Key = `${session.user.username}/${nameBase}-${Date.now()}${ext}`;
    const fileId = `${Date.now()}-${crypto.randomUUID()}`;
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    
    const command = new PutObjectCommand({ 
    Bucket: bucket, 
    Key: r2Key, 
    ContentType: type,
    // 👇 ဒီစာကြောင်း ထပ်ဖြည့်ပါ 👇
    ContentDisposition: `attachment; filename="${encodeURIComponent(name)}"`
});
    const url = await getSignedUrl(client, command, { expiresIn: 10800 });
    return c.json({ url, key: r2Key, fileId });
});

app.post("/api/upload/remote", async (c) => {
    // Rate limit 20
    if(!await checkRateLimit(c, "upload_remote", 20)) return c.json({error: "Too many requests"}, 429);
    
    const session = await getSessionUser(c);
    if(!session || !isVipActive(session.user)) return c.json({error: "VIP Only"}, 403);
    const { url, customName, server, expiry, csrf } = await c.req.json();
    if(csrf !== session.csrfToken) return c.json({error: "Invalid CSRF"}, 403);

    if (await isMaintenanceMode() && session.user.username !== ADMIN_USERNAME) return c.json({ error: "Maintenance Mode On" }, 503);

    try {
        await validateRemoteUrl(url); 
    } catch (e) {
        return c.json({ error: e.message }, 400);
    }

    const bodyStream = new ReadableStream({
        async start(controller) {
            const enc = new TextEncoder();
            const push = (d: any) => controller.enqueue(enc.encode(JSON.stringify(d) + "\n"));
            
            try {
                const r = await fetch(url);
                if(!r.ok) throw new Error("Fetch Failed");
                
                const totalSize = parseInt(r.headers.get("content-length") || "0");
                const limitBytes = PLANS[session.user.plan]?.limit || PLANS.free.limit;
                const requiredSize = (server === "both") ? totalSize * 2 : totalSize;
                
                if(totalSize > MAX_REMOTE_SIZE) throw new Error("File too large (Max 15GB)");
                if(session.user.usedStorage + requiredSize > limitBytes) throw new Error("Storage Full");

                let contentType = r.headers.get("content-type") || "application/octet-stream";
                
                // --- MAGIC NUMBER DETECTION (ဗီဒီယို အစစ်ဟုတ်မဟုတ် စစ်ဆေးခြင်း) ---
                // Stream ရဲ့ အစပိုင်းကို ဖတ်ပြီး Signature စစ်ပါမယ်
                const reader = r.body!.getReader();
                const { value: firstChunk, done } = await reader.read();
                
                if (done) throw new Error("Empty File");

                // ပထမ 16 bytes ကို Hex string ပြောင်းကြည့်မယ်
                const hex = [...new Uint8Array(firstChunk.slice(0, 16))].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
                
                let detectedExt = null;
                // MP4/MOV Signature (....ftyp)
                if (hex.includes("66747970")) { 
                    detectedExt = "mp4";
                    contentType = "video/mp4"; // Content-Type ပါ ပြင်ပေးလိုက်မယ်
                }
                // MKV/WebM Signature (1A 45 DF A3)
                else if (hex.startsWith("1A45DFA3")) {
                    detectedExt = "mkv";
                    contentType = "video/x-matroska";
                }
                // AVI Signature (RIFF)
                else if (hex.startsWith("52494646")) {
                    detectedExt = "avi";
                    contentType = "video/x-msvideo";
                }

                // Extension သတ်မှတ်ခြင်း
                let ext = "";
                
                if (detectedExt) {
                    // ဗီဒီယိုအစစ်ဆိုရင် URL က .txt ဖြစ်နေလည်း ဂရုမစိုက်ဘဲ .mp4/.mkv တပ်မယ်
                    ext = detectedExt;
                } else {
                    // ဗီဒီယိုမဟုတ်ရင် မူလနည်းအတိုင်း စစ်မယ်
                    ext = mimeToExt(contentType); 
                    if (ext === 'bin' || ext === 'txt') {
                        try {
                            const urlObj = new URL(url);
                            const urlExt = urlObj.pathname.split('.').pop()?.toLowerCase();
                            if (urlExt && ALLOWED_EXTENSIONS.has(urlExt)) {
                                ext = urlExt;
                            }
                        } catch (e) {}
                    }
                }

                if (BLOCKED_EXTENSIONS.has(ext)) throw new Error("Blocked File Type");

                const safeName = (customName || "remote").replace(/[^a-zA-Z0-9.\-_\u1000-\u109F]/g, "_");
                let fileName = safeName.includes('.') ? safeName : safeName + '.' + ext;
                
                // --- STREAM RECONSTRUCTION ---
                // စောနက ဖတ်လိုက်တဲ့ firstChunk ကို Stream ထဲ ပြန်ထည့်ပေါင်းပေးရပါမယ်
                // မဟုတ်ရင် ဖိုင်ထိပ်ပိုင်း ပျက်သွားပါလိမ့်မယ်
                const finalStream = new ReadableStream({
                    start(ctrl) {
                        ctrl.enqueue(firstChunk); // ဖတ်ပြီးသား အပိုင်းကို အရင်ထည့်
                    },
                    async pull(ctrl) {
                        // ကျန်တာတွေကို ဆက်ဖတ်ပြီး ပို့
                        const { value, done } = await reader.read();
                        if (done) {
                            ctrl.close();
                        } else {
                            ctrl.enqueue(value);
                        }
                    },
                    cancel() {
                        reader.cancel();
                    }
                });

                // -----------------------------

                const userKey = ["users", session.user.username];
                const uRes = await kv.get<User>(userKey);
                if (!uRes.value) throw Error("User not found");
                if (uRes.value.usedStorage + requiredSize > limitBytes) throw Error("Storage Full");

                const prepareUpload = (svr: "1" | "2", stream: ReadableStream) => {
                    const client = svr === "1" ? s3Server1 : s3Server2;
                    const bucket = svr === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
                    const parts = fileName.lastIndexOf('.');
                    const nameBase = parts !== -1 ? fileName.substring(0, parts) : fileName;
                    const fExt = parts !== -1 ? fileName.substring(parts) : '';
                    const r2Key = `${session.user.username}/${nameBase}-${Date.now()}${fExt}`;
                    const fileId = `${Date.now()}-${crypto.randomUUID()}`;
                    
                    const upload = new Upload({ 
    client, 
    params: { 
        Bucket: bucket, 
        Key: r2Key, 
        Body: stream as any, 
        ContentType: contentType,
        // 👇 ဒီစာကြောင်း ထပ်ဖြည့်ပါ 👇
        ContentDisposition: `attachment; filename="${encodeURIComponent(fileName)}"` 
    }, 
    queueSize: 15, 
    partSize: 10 * 1024**2 
});
                    return { upload, fileId, r2Key, svr };
                };

                let uploads = [];
                if (server === "both") {
                    // finalStream ကို tee လုပ်ပြီး ခွဲပို့
                    const [s1, s2] = finalStream.tee();
                    uploads.push(prepareUpload("1", s1));
                    uploads.push(prepareUpload("2", s2));
                } else {
                    uploads.push(prepareUpload(server, finalStream));
                }

                uploads[0].upload.on("httpUploadProgress", p => { if(totalSize) push({progress: Math.round((p.loaded! / totalSize) * 100)}); });

                await Promise.all(uploads.map(async (u) => {
                    await u.upload.done();
                    const expiryDays = parseInt(expiry) || 0;
                    const type = contentType.startsWith("image/") ? "image" : contentType.startsWith("video/") ? "video" : "other";
                    const fileData: FileData = { id: u.fileId, name: fileName, sizeBytes: totalSize, size: (totalSize / 1024**2).toFixed(2) + " MB", server: u.svr, r2Key: u.r2Key, uploadedAt: Date.now(), expiresAt: expiryDays > 0 ? Date.now() + (expiryDays * 86400000) : 0, type, isVipFile: true };
                    await kv.atomic().set(["files", session.user.username, u.fileId], fileData).commit();
                }));

                let committed = false;
                while (!committed) {
                    const res = await kv.get<User>(userKey);
                    if (!res.value) break;
                    const newUser = { ...res.value, usedStorage: res.value.usedStorage + requiredSize };
                    const status = await kv.atomic().check(res).set(userKey, newUser).commit();
                    committed = status.ok;
                }

                await updateStats(requiredSize);
                push({done: true});
            } catch (e: any) { 
                push({error: e.message}); 
            }
            // Note: Controller closed inside stream pull
        }
    });
    return new Response(bodyStream, { headers: { "Content-Type": "application/x-ndjson" } });
});

app.post("/api/file/edit", async (c) => {
    const session = await getSessionUser(c);
    if(!session || !isVipActive(session.user)) return c.json({error: "VIP Only"}, 403);
    const { fileId, days, csrf } = await c.req.json();
    if(csrf !== session.csrfToken) return c.json({error: "Invalid CSRF"}, 403);
    const fileRes = await kv.get<FileData>(["files", session.user.username, fileId]);
    if(!fileRes.value) return c.json({error: "File not found"}, 404);
    const file = fileRes.value; const addDays = parseInt(days);
    file.expiresAt = addDays === 0 ? 0 : Date.now() + (addDays * 86400000);
    await kv.set(["files", session.user.username, fileId], file);
    return c.json({success: true});
});

app.post("/api/upload/complete", async (c) => {
    // 100% ပြည့်ပြီးခါမှ Fail ဖြစ်တာမျိုး မဖြစ်စေချင်လို့ Rate Limit နည်းနည်းတိုးပေးထားပါတယ်
    if(!await checkRateLimit(c, "upload_complete", 50)) return c.json({error: "Slow down"}, 429);
    
    const session = await getSessionUser(c); 
    if(!session) return c.json({error: "Unauthorized"}, 401);
    
    const { key, fileId, server, expiry, csrf } = await c.req.json();
    if(csrf !== session.csrfToken) return c.json({error: "Invalid CSRF"}, 403);

    const isVip = isVipActive(session.user);
    const expiryDays = isVip ? (parseInt(expiry) || 0) : 30; 
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    
    try {
        // R2 မှာ ဖိုင်ရောက်မရောက် စစ်ဆေးခြင်း
        const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
        const sizeBytes = head.ContentLength || 0;
        
        // ဖိုင်နာမည်ကို Key ကနေ ပြန်ဆွဲထုတ်ခြင်း (Local Upload မှာ Browser ကပေးတဲ့ နာမည်အတိုင်း ဝင်ပါတယ်)
        const fileName = key.split('/').pop().replace(/-\d+(\.[a-zA-Z0-9]+)?$/, "$1");
        
        // Type ကို R2 ကနေ ပြန်ယူမယ် (Browser က တင်လိုက်တဲ့ Type အတိုင်းဖြစ်ပါမယ်)
        const type = head.ContentType?.startsWith("image/") ? "image" : head.ContentType?.startsWith("video/") ? "video" : "other";
        
        const fileData: FileData = { 
            id: fileId, 
            name: fileName, 
            sizeBytes, 
            size: (sizeBytes / 1024**2).toFixed(2) + " MB", 
            server, 
            r2Key: key, 
            uploadedAt: Date.now(), 
            expiresAt: expiryDays > 0 ? Date.now() + (expiryDays * 86400000) : 0, 
            type, 
            isVipFile: isVip 
        };
        
        // Atomic Storage Update
        const userKey = ["users", session.user.username];
        let committed = false;
        while (!committed) {
            const res = await kv.get<User>(userKey);
            if (!res.value) throw new Error("User missing");
            const newUser = { ...res.value, usedStorage: res.value.usedStorage + sizeBytes };
            const status = await kv.atomic()
                .check(res)
                .set(userKey, newUser)
                .set(["files", session.user.username, fileId], fileData)
                .commit();
            committed = status.ok;
        }

        await updateStats(sizeBytes);
        return c.json({ success: true });
    } catch(e) { 
        console.error("Upload Complete Error:", e); // Error Log ကြည့်လို့ရအောင်
        // 404 ဆိုရင် S3 မှာ ဖိုင်မရောက်သေးလို့ပါ
        return c.json({ error: "Verification Failed: File not found on server." }, 500); 
    }
});


// =======================
// 6. ADMIN PANEL
// =======================
app.get("/admin", async (c) => { 
    const session = await getSessionUser(c);
    if(!session || session.user.username !== ADMIN_USERNAME) return c.redirect("/"); 
    const { user: admin, csrfToken } = session;

    const statsRes = await kv.get<{totalUsers: number, totalStorage: number}>(["stats", "global"]);
    const stats = statsRes.value || { totalUsers: 0, totalStorage: 0 };
    const totalGB = (stats.totalStorage / 1024**3).toFixed(2);
    const maintenance = await isMaintenanceMode();

    const searchUser = c.req.query("u");
    const cursor = c.req.query("cursor");
    const users = [];
    let nextCursor = "";

    if(searchUser) {
        const u = await kv.get<User>(["users", searchUser]);
        if(u.value) users.push(u.value);
    } else {
        const iter = kv.list<User>({ prefix: ["users"] }, { limit: 20, cursor: cursor }); 
        for await (const res of iter) { users.push(res.value); nextCursor = res.cursor; }
    }
    
    return c.html(<Layout title="Admin Panel" user={admin} csrfToken={csrfToken}><div class="space-y-6">
        <div class="grid grid-cols-2 gap-3">
            <div class="glass p-4 rounded-xl border-l-4 border-yellow-500 relative"><p class="text-[10px] text-gray-400 uppercase font-bold tracking-wider">Total Users</p><p class="text-2xl font-black mt-1 text-white">{stats.totalUsers}</p></div>
            <div class="glass p-4 rounded-xl border-l-4 border-blue-500 relative"><p class="text-[10px] text-gray-400 uppercase font-bold tracking-wider">Storage Used</p><p class="text-2xl font-black mt-1 text-white">{totalGB} <span class="text-sm font-normal text-gray-500">GB</span></p></div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="glass p-4 rounded-xl flex items-center justify-between">
                <div><h3 class="font-bold text-white">Maintenance</h3><p class="text-xs text-gray-500">Block regular users</p></div>
                <form action="/admin/maintenance" method="post"><input type="hidden" name="csrf" value={csrfToken} /><button class={`px-4 py-2 rounded-lg font-bold text-xs ${maintenance ? 'bg-red-600' : 'bg-green-600'}`}>{maintenance ? "Turn OFF" : "Turn ON"}</button></form>
            </div>
            <div class="glass p-4 rounded-xl flex items-center justify-between">
                <div><h3 class="font-bold text-white">Sync Stats</h3><p class="text-xs text-gray-500">Fix counters</p></div>
                <form action="/admin/recalc-stats" method="post"><input type="hidden" name="csrf" value={csrfToken} /><button class="px-4 py-2 rounded-lg font-bold text-xs bg-blue-600 hover:bg-blue-500 text-white"><i class="fa-solid fa-rotate-right mr-1"></i> Recalc</button></form>
            </div>
        </div>
        
        <div class="glass rounded-xl overflow-hidden border border-zinc-700/50">
            <div class="bg-zinc-800/50 px-4 py-3 border-b border-zinc-700 flex items-center justify-between gap-4">
                <h3 class="font-bold text-white text-sm whitespace-nowrap">User Manager</h3>
                <form class="flex w-full max-w-xs gap-2">
                     <input name="u" placeholder="Search User..." value={searchUser || ''} class="bg-black border border-zinc-600 rounded text-xs px-2 py-1 text-white w-full outline-none focus:border-yellow-500" />
                     <button class="bg-yellow-600 text-black px-3 py-1 rounded text-xs font-bold">Search</button>
                </form>
            </div>
            <div class="overflow-x-auto w-full">
                <table class="w-full text-left text-sm text-gray-400 min-w-[700px]"> 
                    <thead class="bg-zinc-900 text-[10px] uppercase font-bold text-gray-300 tracking-wider"><tr><th class="px-4 py-3">User</th><th class="px-4 py-3">Plan</th><th class="px-4 py-3">Expiry</th><th class="px-4 py-3 text-center">Update Plan</th><th class="px-4 py-3 text-center">Actions</th></tr></thead>
                    <tbody class="divide-y divide-zinc-700/50">{users.map(u => {
                        const planName = PLANS[u.plan]?.name || "Legacy";
                        return (
                        <tr class={`hover:bg-zinc-800/40 transition ${u.isBanned ? 'bg-red-900/10' : ''}`}>
                            <td class="px-4 py-3 font-bold text-white">{u.username}{u.isBanned && <span class="ml-2 bg-red-600 text-[9px] px-1 rounded text-white">BANNED</span>}</td>
                            <td class="px-4 py-3 text-xs">{planName}</td>
                            <td class="px-4 py-3 text-xs">{u.vipExpiry ? formatDate(u.vipExpiry) : '-'}</td>
                            <td class="px-4 py-3 text-center">
                                <form action="/admin/update-plan" method="post" class="flex gap-1 justify-center">
                                    <input type="hidden" name="csrf" value={csrfToken} /><input type="hidden" name="username" value={u.username} />
                                    <select name="plan" class="bg-black border border-zinc-600 rounded text-[10px] py-1 px-2 outline-none w-24">{Object.keys(PLANS).map(k => <option value={k} selected={u.plan === k}>{PLANS[k].name}</option>)}</select>
                                    <select name="months" class="bg-black border border-zinc-600 rounded text-[10px] py-1 px-2 outline-none w-16"><option value="1">+1 Mo</option><option value="6">+6 Mo</option><option value="12">+1 Yr</option><option value="0">Reset</option></select>
                                    <button class="bg-yellow-600 hover:bg-yellow-500 text-black px-2 py-1 rounded text-[10px] font-bold">Save</button>
                                </form>
                            </td>
                            <td class="px-4 py-3 flex items-center justify-center gap-2">
                                <a href={`/admin/files/${u.username}`} class="w-6 h-6 flex items-center justify-center bg-zinc-700 hover:bg-white hover:text-black rounded transition"><i class="fa-solid fa-folder-open text-[10px]"></i></a>
                                {u.username !== ADMIN_USERNAME && <div class="flex gap-1">
                                    <form action="/admin/ban-user" method="post" onsubmit="return confirm('Ban/Unban user?')"><input type="hidden" name="csrf" value={csrfToken} /><input type="hidden" name="username" value={u.username} /><button class={`w-6 h-6 flex items-center justify-center rounded ${u.isBanned ? 'bg-green-600 hover:bg-green-500' : 'bg-orange-600 hover:bg-orange-500'} text-white`}><i class={`fa-solid ${u.isBanned ? 'fa-unlock' : 'fa-ban'} text-[10px]`}></i></button></form>
                                    <form action="/admin/delete-user" method="post" onsubmit="return confirm('Delete user and ALL files?')"><input type="hidden" name="csrf" value={csrfToken} /><input type="hidden" name="username" value={u.username} /><button class="w-6 h-6 flex items-center justify-center bg-red-900/50 text-red-500 hover:bg-red-500 hover:text-white rounded"><i class="fa-solid fa-trash text-[10px]"></i></button></form>
                                    <form action="/admin/reset-pass" method="post" onsubmit="return confirm('Reset pass to 123456?')"><input type="hidden" name="csrf" value={csrfToken} /><input type="hidden" name="username" value={u.username} /><button class="w-6 h-6 flex items-center justify-center bg-blue-900/50 text-blue-500 hover:bg-blue-500 hover:text-white rounded"><i class="fa-solid fa-key text-[10px]"></i></button></form>
                                </div>}
                            </td>
                        </tr>
                    )})}</tbody>
                </table>
            </div>
            {nextCursor && <div class="text-center p-3 border-t border-zinc-800"><a href={`/admin?cursor=${nextCursor}`} class="text-xs bg-zinc-800 hover:bg-white hover:text-black text-gray-400 px-4 py-1.5 rounded-full transition">Next Page <i class="fa-solid fa-chevron-right ml-1"></i></a></div>}
        </div>
    </div></Layout>); 
});
app.get("/admin/files/:username", async (c) => { 
    const session = await getSessionUser(c);
    if(!session || session.user.username !== ADMIN_USERNAME) return c.redirect("/"); 
    const targetUser = c.req.param("username"); 
    const iter = kv.list<FileData>({ prefix: ["files", targetUser] }, { reverse: true, limit: 100 }); 
    const files = []; for await (const res of iter) files.push(res.value); 
    return c.html(<Layout title={`Files: ${targetUser}`} user={session.user} csrfToken={session.csrfToken}>
        <div class="flex items-center justify-between mb-6"><h2 class="text-xl font-bold text-white"><span class="text-yellow-500">{targetUser}</span>'s Files</h2><a href="/admin" class="bg-zinc-800 px-4 py-2 rounded-lg text-sm hover:bg-zinc-700">Back</a></div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">{files.map(f => (<div class="glass p-3 rounded-xl group relative"><div class="h-24 bg-zinc-900/50 rounded-lg flex items-center justify-center mb-2 overflow-hidden relative">{f.type === 'image' ? (<img loading="lazy" src={`${STREAM_DOMAIN}/d/${f.server}/${f.r2Key}`} class="w-full h-full object-cover opacity-70 group-hover:opacity-100 transition" />) : (<i class={`fa-solid ${f.type === 'video' ? 'fa-clapperboard text-blue-500' : 'fa-file text-zinc-600'} text-3xl`}></i>)}</div><p class="text-xs font-bold text-white truncate">{f.name}</p><p class="text-[10px] text-zinc-500">S{f.server} • {f.size} • {f.expiresAt ? formatDate(f.expiresAt) : "Lifetime"}</p><div class="absolute inset-0 bg-black/80 flex items-center justify-center gap-2 opacity-0 group-hover:opacity-100 transition rounded-xl"><a href={`${STREAM_DOMAIN}/d/${f.server}/${f.r2Key}`} target="_blank" class="w-8 h-8 flex items-center justify-center bg-blue-600 text-white rounded-full"><i class="fa-solid fa-eye text-xs"></i></a><form action={`/delete/${f.id}`} method="post" onsubmit="return confirm('Delete file?')"><input type="hidden" name="csrf" value={session.csrfToken} /><button class="w-8 h-8 flex items-center justify-center bg-red-600 text-white rounded-full"><i class="fa-solid fa-trash text-xs"></i></button></form></div></div>))}</div>
    </Layout>); 
});

async function checkAdmin(c: any) { const s = await getSessionUser(c); if(s && s.user.username === ADMIN_USERNAME) { const body = await c.req.parseBody(); if(body.csrf === s.csrfToken) return body; } return null; }
app.post("/admin/maintenance", async (c) => { const body = await checkAdmin(c); if(!body) return c.text("403"); const current = await isMaintenanceMode(); await kv.set(["config", "system"], { maintenance: !current }); return c.redirect("/admin"); });
app.post("/admin/recalc-stats", async (c) => { const body = await checkAdmin(c); if(!body) return c.text("403"); let tu=0; let ts=0; const iter = kv.list<User>({ prefix: ["users"] }); for await (const res of iter) { tu++; ts += res.value.usedStorage; } await kv.set(["stats", "global"], { totalUsers: tu, totalStorage: ts }); return c.redirect("/admin"); });
app.post("/admin/update-plan", async (c) => { const body = await checkAdmin(c); if(!body) return c.text("403"); const user = (await kv.get<User>(["users", String(body.username)])).value; if(user) { user.plan = String(body.plan) as keyof typeof PLANS; const addMonths = parseInt(String(body.months)); if (addMonths === 0) { user.vipExpiry = undefined; user.plan = 'free'; } else { const now = Date.now(); const currentExp = (user.vipExpiry && user.vipExpiry > now) ? user.vipExpiry : now; user.vipExpiry = currentExp + (addMonths * 30 * 24 * 60 * 60 * 1000); } await kv.set(["users", user.username], user); } return c.redirect("/admin"); });
app.post("/admin/ban-user", async (c) => { const body = await checkAdmin(c); if(!body) return c.text("403"); const user = (await kv.get<User>(["users", String(body.username)])).value; if(user && user.username !== ADMIN_USERNAME) { user.isBanned = !user.isBanned; await kv.set(["users", user.username], user); } return c.redirect("/admin"); });
app.post("/admin/delete-user", async (c) => { const body = await checkAdmin(c); if(!body) return c.text("403"); const u = String(body.username); const iter = kv.list<FileData>({ prefix: ["files", u] }); let rs = 0; for await (const res of iter) { await deleteFileFromR2(res.value); await kv.delete(res.key); rs+=res.value.sizeBytes; } await kv.delete(["users", u]); await updateStats(-rs); return c.redirect("/admin"); });
app.post("/admin/reset-pass", async (c) => { const body = await checkAdmin(c); if(!body) return c.text("403"); const u = String(body.username); const user = (await kv.get<User>(["users", u])).value; if(user) { user.passwordHash = await hashPassword("123456"); await kv.set(["users", u], user); } return c.redirect("/admin"); });

async function deleteFileFromR2(f: FileData) { const bucket = Deno.env.get(`R2_${f.server}_BUCKET_NAME`); const client = f.server === "1" ? s3Server1 : s3Server2; try { await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: f.r2Key })); } catch (e) {} }

app.post("/delete/:id", async (c) => { 
    const session = await getSessionUser(c); if(!session) return c.redirect("/login");
    const { csrf } = await c.req.parseBody(); if(csrf !== session.csrfToken) return c.text("Invalid CSRF", 403);
    const id = c.req.param("id"); 
    const fileRes = await kv.get<FileData>(["files", session.user.username, id]); 
    if (fileRes.value) { 
        await deleteFileFromR2(fileRes.value); 
        // Atomic decrement
        let committed = false;
        while(!committed) {
             const uRes = await kv.get<User>(["users", session.user.username]);
             if(!uRes.value) break;
             const newUser = { ...uRes.value, usedStorage: Math.max(0, uRes.value.usedStorage - fileRes.value.sizeBytes) };
             const status = await kv.atomic().check(uRes).set(["users", session.user.username], newUser).delete(["files", session.user.username, id]).commit();
             committed = status.ok;
        }
        await updateStats(-fileRes.value.sizeBytes); 
    } 
    return c.redirect("/"); 
});

// =======================
// 7. AUTH ROUTES
// =======================
app.get("/login", (c) => c.html(
    <Layout title="Login" hideLoginLink={true}>
        <div class="max-w-sm mx-auto mt-24 glass p-8 rounded-2xl border border-zinc-700">
            <h1 class="text-3xl font-black mb-2 text-center text-yellow-500 italic">GOLD STORAGE</h1>
            <form action="/login" method="post" class="space-y-4" onsubmit="setLoading('btnLogin', true, 'Checking...')">
                <input name="username" placeholder="အမည် (Username)" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white outline-none focus:border-yellow-500" />
                <input type="password" name="password" placeholder="စကားဝှက် (Password)" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white outline-none focus:border-yellow-500" />
                <button id="btnLogin" class="w-full bg-yellow-500 text-black font-bold py-3 rounded-xl hover:bg-yellow-400">ဝင်မည်</button>
            </form>
            <p class="text-center text-xs mt-6 text-zinc-500">အကောင့်မရှိဘူးလား? <a href="/register" class="text-yellow-500 font-bold hover:underline">အကောင့်သစ်ဖွင့်မယ်</a></p>
        </div>
    </Layout>
));
app.post("/login", async (c) => { 
    if(!await checkRateLimit(c, "login", 10)) return c.html(<Layout hideLoginLink={true}><p class="text-center text-red-500 mt-20">Too many attempts. Wait 1 min.</p></Layout>);
    const { username, password } = await c.req.parseBody(); const u = String(username).trim(); 
    const userRes = await kv.get<User>(["users", u]);
    if (userRes.value && userRes.value.passwordHash === await hashPassword(String(password).trim())) { await createSession(c, u); return c.redirect("/"); } 
    return c.html(<Layout hideLoginLink={true}><div class="max-w-sm mx-auto mt-24 glass p-8 rounded-2xl"><p class="text-center text-red-500 mb-4 font-bold">Username (သို့) Password မှားနေပါသည်</p><div class="text-center"><a href="/login" class="text-white bg-zinc-800 px-4 py-2 rounded">နောက်တစ်ခေါက် ကြိုးစားမည်</a></div></div></Layout>); 
});
app.get("/register", (c) => c.html(
    <Layout title="Register" hideLoginLink={true}>
        <div class="max-w-sm mx-auto mt-24 glass p-8 rounded-2xl border border-zinc-700">
            <h1 class="text-xl font-bold mb-6 text-center text-white">အကောင့်သစ်ဖွင့်မည်</h1>
            <form action="/register" method="post" class="space-y-4" onsubmit="setLoading('btnReg', true, 'Creating Account...')">
                <input name="username" placeholder="Username (Min 3 chars)" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white" />
                <input type="password" name="password" placeholder="Password (Min 6 chars)" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white" />
                <button id="btnReg" class="w-full bg-green-600 hover:bg-green-500 py-3 rounded-xl font-bold text-white">စာရင်းသွင်းမည်</button>
            </form>
            <p class="text-center text-xs mt-6 text-zinc-500">အကောင့်ရှိပြီးသားလား? <a href="/login" class="text-yellow-500 font-bold hover:underline">ဝင်မည်</a></p>
        </div>
    </Layout>
));
app.post("/register", async (c) => { 
    if(!await checkRateLimit(c, "register", 5)) return c.text("Slow down", 429);
    const { username, password } = await c.req.parseBody(); 
    const u = String(username).trim().replace(/[^a-zA-Z0-9]/g, ""); 
    if(u.length < 3) return c.html(<Layout><p class="text-center text-red-500 mt-20">Username too short (Min 3 chars).</p></Layout>);
    if(String(password).length < 6) return c.html(<Layout><p class="text-center text-red-500 mt-20">Password too short (Min 6 chars).</p></Layout>);
    
    const userKey = ["users", u];
    const newUser: User = { username: u, passwordHash: await hashPassword(String(password)), plan: 'free', isVip: false, usedStorage: 0, createdAt: Date.now() };
    
    const res = await kv.atomic().check({ key: userKey, versionstamp: null }).set(userKey, newUser).commit();
    if (!res.ok) return c.html(<Layout><p class="text-center text-red-500 mt-20">Username Taken.</p><div class="text-center mt-4"><a href="/register" class="bg-zinc-800 text-white px-4 py-2 rounded">Try Again</a></div></Layout>); 
    
    await incrementUserCount();
    return c.redirect("/login"); 
});
app.get("/logout", async (c) => { const sid = getCookie(c, "session_id"); if(sid) await kv.delete(["sessions", sid]); deleteCookie(c, "session_id"); return c.redirect("/login"); });

app.get("/change-password", async (c) => {
    const session = await getSessionUser(c);
    if (!session) return c.redirect("/login");
    return c.html(
        <Layout title="Change Password" user={session.user} csrfToken={session.csrfToken}>
            <div class="max-w-sm mx-auto mt-20 glass p-8 rounded-xl">
                <h1 class="text-xl font-bold mb-4 text-white">စကားဝှက်ပြောင်းမည်</h1>
                <form action="/change-password" method="post" class="space-y-4">
                    <input type="password" name="newpass" placeholder="New Password" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white" />
                    <button class="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-bold text-white">အတည်ပြုမည်</button>
                </form>
                <a href="/" class="block text-center mt-4 text-xs text-gray-400">Back</a>
            </div>
        </Layout>
    );
});
app.post("/change-password", async (c) => { 
    const session = await getSessionUser(c); if(!session) return c.redirect("/login");
    const { newpass } = await c.req.parseBody(); if(String(newpass).length < 6) return c.text("Min 6 chars"); 
    session.user.passwordHash = await hashPassword(String(newpass)); await kv.set(["users", session.user.username], session.user); 
    return c.html(<Layout><div class="text-center mt-20"><p class="text-green-500 text-xl font-bold mb-4">Success!</p><a href="/" class="bg-zinc-800 px-4 py-2 rounded-lg text-sm text-white">Home</a></div></Layout>); 
});

// Cron Jobs
Deno.cron("Cleanup", "0 * * * *", async () => { 
    const now = Date.now(); const iter = kv.list<FileData>({ prefix: ["files"] }); 
    for await (const entry of iter) { 
        const file = entry.value; const username = entry.key[1] as string; const uRes = await kv.get<User>(["users", username]);
        if (uRes.value) {
            const user = uRes.value;
            // Expired file OR User VIP expired > 7 days
            if ((file.expiresAt > 0 && file.expiresAt < now) || (user.vipExpiry && user.vipExpiry < now && now > user.vipExpiry + (7 * 86400000))) { 
                await deleteFileFromR2(file); 
                 let committed = false;
                 while(!committed) {
                     const u = await kv.get<User>(["users", user.username]);
                     if(!u.value) break;
                     const nu = { ...u.value, usedStorage: Math.max(0, u.value.usedStorage - file.sizeBytes) };
                     const s = await kv.atomic().check(u).set(["users", user.username], nu).delete(entry.key).commit();
                     committed = s.ok;
                 }
                await updateStats(-file.sizeBytes); 
            }
        } else { await kv.delete(entry.key); } 
    } 
});

Deno.serve(app.fetch);
