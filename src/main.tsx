/** @jsxImportSource npm:hono@4/jsx */ 
import { Hono, Context } from "npm:hono@4";
import { getCookie, setCookie, deleteCookie } from "npm:hono@4/cookie";
import { secureHeaders } from "npm:hono@4/secure-headers";
import { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand, HeadObjectCommand } from "npm:@aws-sdk/client-s3";
import { getSignedUrl } from "npm:@aws-sdk/s3-request-presigner";
import { Upload } from "npm:@aws-sdk/lib-storage"; 
import { html } from "npm:hono@4/html";

// =======================
// 1. CONFIGURATION
// =======================
const REQUIRED_ENVS = ["ADMIN_USERNAME", "SECRET_SALT", "R2_1_ACCOUNT_ID", "R2_1_ACCESS_KEY_ID", "R2_1_SECRET_ACCESS_KEY", "R2_1_BUCKET_NAME", "R2_2_ACCOUNT_ID"];
for(const e of REQUIRED_ENVS) { if(!Deno.env.get(e)) throw new Error(`Missing ENV: ${e}`); }

const app = new Hono();

app.use('*', secureHeaders({
    contentSecurityPolicy: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
    }
}));

const kv = await Deno.openKv();

const ADMIN_USERNAME = Deno.env.get("ADMIN_USERNAME") || "admin"; 
const SECRET_KEY = Deno.env.get("SECRET_SALT")!;
const MAX_REMOTE_SIZE = 2 * 1024 * 1024 * 1024; // 2 GB
const ALLOWED_EXTENSIONS = new Set(['jpg','jpeg','png','gif','webp','mp4','mkv','webm','mov','mp3','wav','zip','rar','7z','pdf','txt','doc','docx']);
const BLOCKED_EXTENSIONS = new Set(['exe','sh','php','pl','py','js','html','htm','css','bat','cmd','msi','svg','xml','jar','vbs']);

const PLANS = {
    free:  { limit: 50 * 1024 * 1024 * 1024, name: "Free Plan" },
    vip50: { limit: 50 * 1024 * 1024 * 1024, name: "50 GB VIP" },
    vip100:{ limit: 100 * 1024 * 1024 * 1024, name: "100 GB VIP" },
    vip300:{ limit: 300 * 1024 * 1024 * 1024, name: "300 GB VIP" },
    vip500:{ limit: 500 * 1024 * 1024 * 1024, name: "500 GB VIP" },
    vip1t: { limit: 1000 * 1024 * 1024 * 1024, name: "1 TB VIP" },
};

// S3 Clients
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

// =======================
// 2. TYPES & HELPERS
// =======================
interface User { 
    username: string; passwordHash: string; plan: keyof typeof PLANS; isVip: boolean; vipExpiry?: number; usedStorage: number; createdAt: number; isBanned?: boolean;
}
interface Session { username: string; expires: number; csrfToken: string; }
interface FileData { id: string; name: string; sizeBytes: number; size: string; server: "1" | "2"; r2Key: string; uploadedAt: number; expiresAt: number; type: "image" | "video" | "other"; isVipFile: boolean; }
interface JobData { id: string; username: string; name: string; status: "pending" | "processing" | "completed" | "failed"; progress: number; totalSize: string; error?: string; createdAt: number; }
interface SystemConfig { maintenance: boolean; }

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

async function createSession(c: Context, username: string) {
    const sessionId = crypto.randomUUID();
    const csrfToken = crypto.randomUUID();
    await kv.set(["sessions", sessionId], { username, expires: Date.now() + 604800000, csrfToken }, { expireIn: 604800000 });
    setCookie(c, "session_id", sessionId, { path: "/", httpOnly: true, secure: true, sameSite: "Lax", maxAge: 604800 });
}

async function getSessionUser(c: Context): Promise<{ user: User, csrfToken: string } | null> {
    const sessionId = getCookie(c, "session_id");
    if (!sessionId) return null;
    const res = await kv.get<Session>(["sessions", sessionId]);
    if (!res.value || res.value.expires < Date.now()) return null;
    const uRes = await kv.get<User>(["users", res.value.username]);
    if (!uRes.value) return null;
    const user = uRes.value;
    if (!user.plan || !PLANS[user.plan]) { user.plan = user.isVip ? 'vip50' : 'free'; await kv.set(["users", user.username], user); }
    return { user, csrfToken: res.value.csrfToken };
}

function isValidRemoteUrl(urlString: string): boolean {
    try {
        const url = new URL(urlString);
        if (!['http:', 'https:'].includes(url.protocol)) return false;
        const host = url.hostname;
        if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]') return false;
        if (host.startsWith('192.168.') || host.startsWith('10.') || host.match(/^172\.(1[6-9]|2\d|3[0-1])\./)) return false;
        if (host.endsWith('.local') || host.endsWith('.internal')) return false;
        return true;
    } catch { return false; }
}

function validateFileName(name: string): { valid: boolean, error?: string, safeName?: string, ext?: string } {
    const ext = name.split('.').pop()?.toLowerCase() || '';
    if (BLOCKED_EXTENSIONS.has(ext)) return { valid: false, error: "Security Restriction: This file type is not allowed." };
    const safeName = name.replace(/[^a-zA-Z0-9.\-_\u1000-\u109F]/g, "_");
    return { valid: true, safeName, ext };
}

function isVipActive(user: User): boolean { if (user.plan === 'free') return false; return user.vipExpiry ? user.vipExpiry > Date.now() : false; }
function formatDate(ts: number) { return new Date(ts).toLocaleDateString('my-MM', { day: 'numeric', month: 'short', year: 'numeric' }); }
function mimeToExt(mime: string): string { const m: any = {'video/mp4':'mp4','video/webm':'webm','video/x-matroska':'mkv','image/jpeg':'jpg','image/png':'png', 'image/gif':'gif'}; return m[mime.split(';')[0]] || 'bin'; }

// =======================
// 3. FRONTEND COMPONENTS
// =======================
const ToastScript = `
<script>
    function showToast(message, type = 'success') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        const bgColor = type === 'error' ? 'bg-red-600' : 'bg-green-600';
        toast.className = \`\${bgColor} text-white px-6 py-3 rounded-xl shadow-2xl flex items-center gap-3 transform transition-all duration-300 translate-y-10 opacity-0\`;
        toast.innerHTML = \`<i class="fa-solid \${type==='error'?'fa-triangle-exclamation':'fa-check-circle'}"></i> <span class="font-bold text-sm">\${message}</span>\`;
        container.appendChild(toast);
        requestAnimationFrame(() => toast.classList.remove('translate-y-10', 'opacity-0'));
        setTimeout(() => { toast.classList.add('translate-y-10', 'opacity-0'); setTimeout(() => toast.remove(), 300); }, 3000);
    }
    function setLoading(btnId, isLoading, text = 'Loading...') {
        const btn = document.getElementById(btnId);
        if(!btn) return;
        if(isLoading) { btn.dataset.originalText = btn.innerHTML; btn.disabled = true; btn.innerHTML = \`<i class="fa-solid fa-circle-notch fa-spin"></i> \${text}\`; btn.classList.add('opacity-75', 'cursor-not-allowed'); } 
        else { btn.disabled = false; btn.innerHTML = btn.dataset.originalText || 'Submit'; btn.classList.remove('opacity-75', 'cursor-not-allowed'); }
    }
</script>
`;

const MainScript = `
<script>
    const IS_USER_VIP = window.IS_VIP_USER || false;
    let targetFileId = null; 

    // --- Job Polling ---
    const activeJobs = new Set();
    
    async function startJobPolling(jobId) {
        if(activeJobs.has(jobId)) return;
        activeJobs.add(jobId);
        
        const jobCard = document.createElement('div');
        jobCard.id = 'job-' + jobId;
        jobCard.className = 'bg-zinc-900 border border-zinc-700 p-4 rounded-xl mb-3 animate-pulse';
        jobCard.innerHTML = \`
            <div class="flex justify-between items-center mb-2">
                <span class="text-xs font-bold text-yellow-500 uppercase"><i class="fa-solid fa-cloud-arrow-down mr-2"></i> Remote Upload</span>
                <span class="text-xs text-zinc-400" id="status-\${jobId}">စတင်နေသည်...</span>
            </div>
            <div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden">
                <div id="bar-\${jobId}" class="bg-yellow-500 h-full transition-all duration-500" style="width: 0%"></div>
            </div>
        \`;
        document.getElementById('job-container').prepend(jobCard);
        document.getElementById('job-container').classList.remove('hidden');

        const poll = setInterval(async () => {
            try {
                const res = await fetch('/api/job/' + jobId);
                const data = await res.json();
                
                if(!data || data.error) {
                    clearInterval(poll); activeJobs.delete(jobId);
                    document.getElementById('status-' + jobId).innerText = 'Error';
                    document.getElementById('status-' + jobId).classList.add('text-red-500');
                    return;
                }

                const statusEl = document.getElementById('status-' + jobId);
                const barEl = document.getElementById('bar-' + jobId);
                
                if (data.status === 'processing') {
                    statusEl.innerText = \`ဒေါင်းလုဒ်ဆွဲပြီး ပြန်တင်နေသည် (\${data.progress}%)\`;
                    barEl.style.width = data.progress + '%';
                } else if (data.status === 'completed') {
                    clearInterval(poll); activeJobs.delete(jobId);
                    statusEl.innerText = 'အောင်မြင်ပါသည်';
                    statusEl.classList.add('text-green-500');
                    barEl.style.width = '100%';
                    barEl.classList.add('bg-green-500');
                    setTimeout(() => window.location.reload(), 2000);
                } else if (data.status === 'failed') {
                    clearInterval(poll); activeJobs.delete(jobId);
                    statusEl.innerText = 'မအောင်မြင်ပါ: ' + (data.error || 'Unknown');
                    statusEl.classList.add('text-red-500');
                    barEl.classList.add('bg-red-600');
                }
            } catch(e) { clearInterval(poll); }
        }, 1500); 
    }

    window.EXISTING_JOBS.forEach(id => startJobPolling(id));

    // --- UI Logic ---
    function switchUploadMode(mode) {
        if (mode === 'remote' && !IS_USER_VIP) { document.getElementById('vipModal').classList.remove('hidden'); return; }
        document.querySelectorAll('.upload-mode').forEach(el => el.classList.add('hidden'));
        document.querySelectorAll('.mode-btn').forEach(el => { el.classList.remove('bg-yellow-500', 'text-black'); el.classList.add('bg-zinc-800', 'text-gray-400'); });
        document.getElementById('mode-' + mode).classList.remove('hidden');
        document.getElementById('btn-mode-' + mode).classList.remove('bg-zinc-800', 'text-gray-400');
        document.getElementById('btn-mode-' + mode).classList.add('bg-yellow-500', 'text-black');
    }

    function openDeleteModal(fileId) { targetFileId = fileId; document.getElementById('deleteModal').classList.remove('hidden'); }
    function openDeleteAllModal() { document.getElementById('deleteAllModal').classList.remove('hidden'); }
    function closeModal(id) { document.getElementById(id).classList.add('hidden'); targetFileId = null; }

    async function confirmDelete() {
        if(!targetFileId) return;
        setLoading('btnConfirmDelete', true, 'ဖျက်နေသည်...');
        try {
            const formData = new FormData(); formData.append('csrf', window.CSRF_TOKEN);
            const res = await fetch('/delete/' + targetFileId, { method: 'POST', body: formData });
            if(res.ok) window.location.reload(); else showToast("ဖျက်မရပါ", "error");
        } catch(e) { showToast("Error deleting file", "error"); }
    }

    async function confirmDeleteAll() {
        setLoading('btnConfirmDeleteAll', true, 'ဖျက်နေသည်...');
        try {
            const formData = new FormData(); formData.append('csrf', window.CSRF_TOKEN);
            const res = await fetch('/api/delete-all', { method: 'POST', body: formData });
            if(res.ok) { showToast("ဖိုင်အားလုံး ဖျက်ပြီးပါပြီ"); setTimeout(() => window.location.reload(), 1500); }
            else showToast("Failed to delete all", "error");
        } catch(e) { showToast("Error", "error"); }
    }

    // --- Local Upload ---
    async function uploadLocal(event) {
        event.preventDefault();
        const fileInput = document.getElementById('fileInput');
        if(fileInput.files.length === 0) { showToast("ဖိုင်ရွေးပေးပါ", 'error'); return; }
        setLoading('submitBtn', true, 'စစ်ဆေးနေသည်...');
        document.getElementById('progressContainer').classList.remove('hidden');
        
        try {
            const formData = new FormData(document.getElementById('uploadForm'));
            const presignRes = await fetch("/api/upload/presign", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: fileInput.files[0].name, type: fileInput.files[0].type, size: fileInput.files[0].size, server: formData.get("server"), customName: formData.get("customName"), csrf: window.CSRF_TOKEN })
            });
            const pData = await presignRes.json();
            if (!presignRes.ok) throw new Error(pData.error);
            
            const xhr = new XMLHttpRequest();
            xhr.open("PUT", pData.url, true);
            xhr.setRequestHeader("Content-Type", fileInput.files[0].type);
            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const p = Math.round((e.loaded / e.total) * 100);
                    document.getElementById('progressBar').style.width = p + "%";
                    document.getElementById('progressText').innerText = p + "%";
                }
            };
            xhr.onload = async () => {
                if (xhr.status === 200) {
                    await fetch("/api/upload/complete", { 
                        method: "POST", headers: { "Content-Type": "application/json" }, 
                        body: JSON.stringify({ key: pData.key, fileId: pData.fileId, server: formData.get("server"), expiry: formData.get("expiry"), csrf: window.CSRF_TOKEN }) 
                    });
                    showToast('အောင်မြင်စွာ တင်ပြီးပါပြီ!'); setTimeout(() => window.location.reload(), 1000);
                } else throw new Error("Upload Failed");
            };
            xhr.send(fileInput.files[0]);
        } catch (e) { showToast(e.message, 'error'); setLoading('submitBtn', false); }
    }

    // --- Remote Upload (Background) ---
    async function uploadRemote(event) {
        event.preventDefault();
        const urlInput = document.getElementById('remoteUrl');
        if(!urlInput.value) { showToast("URL ထည့်ပေးပါ", 'error'); return; }
        setLoading('remoteBtn', true, 'စတင်နေသည်...');
        
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
            if(!res.ok) throw new Error(data.error);

            showToast("နောက်ကွယ်တွင် ဆက်လက်လုပ်ဆောင်နေပါသည်");
            urlInput.value = ''; 
            startJobPolling(data.jobId);
            setLoading('remoteBtn', false);
        } catch(e) { showToast(e.message, 'error'); setLoading('remoteBtn', false); }
    }

    document.getElementById('fileInput')?.addEventListener('change', function() {
        if (this.files[0]) document.getElementById('fileNameDisplay').innerText = this.files[0].name;
    });
</script>
`;

const Layout = (props: { children: any; title?: string; user?: User | null, csrfToken?: string, activeJobs?: string[] }) => {
    const isVip = props.user ? isVipActive(props.user) : false;
    const jobList = props.activeJobs ? JSON.stringify(props.activeJobs) : "[]";
    return (
    <html lang="my">
        <head>
            <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>{props.title || "Gold Storage Cloud"}</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" />
            <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap" rel="stylesheet" />
            <style>{`
                body { font-family: 'Padauk', sans-serif; background-color: #050505; color: #e4e4e7; }
                .glass { background: #121212; border: 1px solid #27272a; }
                .vip-card:hover { border-color: #eab308; transform: translateY(-5px); }
                .custom-scroll::-webkit-scrollbar { width: 5px; background: #000; }
                .custom-scroll::-webkit-scrollbar-thumb { background: #333; border-radius: 5px; }
            `}</style>
            <script dangerouslySetInnerHTML={{__html: `window.IS_VIP_USER = ${isVip}; window.CSRF_TOKEN = "${props.csrfToken || ''}"; window.EXISTING_JOBS = ${jobList};`}} />
            <div dangerouslySetInnerHTML={{__html: ToastScript}} />
        </head>
        <body>
            <div id="toast-container" class="fixed top-20 right-5 z-[200] flex flex-col gap-3"></div>
            <nav class="fixed top-0 w-full z-50 glass border-b border-zinc-800 bg-black/80 backdrop-blur-md"><div class="max-w-5xl mx-auto px-4 py-3 flex justify-between items-center"><a href="/" class="text-xl font-black text-white italic tracking-tighter flex items-center gap-2"><i class="fa-solid fa-cube text-yellow-500"></i> <span class="bg-clip-text text-transparent bg-gradient-to-r from-yellow-400 to-yellow-600">GOLD STORAGE</span></a>
            {props.user ? (<div class="flex gap-3 items-center"><span class="text-xs font-bold text-gray-300 hidden sm:block">{props.user.username}</span>{isVipActive(props.user) ? <span class="text-[9px] text-yellow-500 font-bold bg-yellow-500/10 px-1 rounded">VIP</span> : <span class="text-[9px] text-gray-500 font-bold bg-zinc-800 px-1 rounded">FREE</span>}<a href="/logout" class="w-8 h-8 flex items-center justify-center bg-zinc-800 rounded-full hover:bg-red-600/20 hover:text-red-500"><i class="fa-solid fa-power-off text-xs"></i></a></div>) : (<a href="/login" class="text-xs bg-yellow-500 text-black px-4 py-2 rounded-full font-bold">ဝင်မည်</a>)}</div></nav>
            <main class="pt-20 pb-10 px-4 max-w-5xl mx-auto">{props.children}</main>
            
            <div id="vipModal" class="fixed inset-0 bg-black/80 hidden z-50 flex items-center justify-center"><div class="bg-zinc-900 border border-yellow-500 p-6 rounded-2xl w-80 text-center"><i class="fa-solid fa-crown text-3xl text-yellow-500 mb-4"></i><h3 class="font-bold text-white mb-2">VIP ONLY</h3><p class="text-gray-400 text-sm mb-4">Remote Upload သုံးရန် VIP Member ဝင်ပါ။</p><button onclick="closeModal('vipModal')" class="bg-yellow-500 text-black font-bold py-2 px-6 rounded-lg">နားလည်ပါပြီ</button></div></div>
            
            {/* Delete Single File Modal */}
            <div id="deleteModal" class="fixed inset-0 bg-black/80 hidden z-50 flex items-center justify-center"><div class="bg-zinc-900 border border-zinc-700 p-6 rounded-2xl w-80 text-center"><i class="fa-solid fa-trash text-3xl text-red-500 mb-4"></i><h3 class="font-bold text-white mb-2">ဖိုင်ကို ဖျက်မည်လား?</h3><p class="text-xs text-gray-500 mb-4">ပြန်ယူ၍ မရနိုင်ပါ။</p><div class="flex gap-2 mt-4"><button onclick="closeModal('deleteModal')" class="flex-1 bg-zinc-800 py-2 rounded-lg text-white">မဖျက်တော့ပါ</button><button id="btnConfirmDelete" onclick="confirmDelete()" class="flex-1 bg-red-600 text-white py-2 rounded-lg font-bold">ဖျက်မည်</button></div></div></div>

            {/* Delete All Files Modal */}
            <div id="deleteAllModal" class="fixed inset-0 bg-black/90 hidden z-50 flex items-center justify-center"><div class="bg-zinc-900 border border-red-600 p-6 rounded-2xl w-80 text-center"><i class="fa-solid fa-triangle-exclamation text-3xl text-red-500 mb-4 animate-pulse"></i><h3 class="font-bold text-white mb-2 text-lg">သတိပေးချက်!</h3><p class="text-sm text-gray-300 mb-4">ဖိုင် <span class="text-red-500 font-bold">အားလုံး</span> ကို အပြီးတိုင် ဖျက်ပစ်မည်။<br/>ဒီအလုပ်ကို ပြန်ပြင်လို့ မရနိုင်ပါ။</p><div class="flex gap-2 mt-6"><button onclick="closeModal('deleteAllModal')" class="flex-1 bg-zinc-800 py-2 rounded-lg text-white font-bold">မလုပ်တော့ပါ</button><button id="btnConfirmDeleteAll" onclick="confirmDeleteAll()" class="flex-1 bg-red-600 text-white py-2 rounded-lg font-bold">အားလုံးဖျက်မည်</button></div></div></div>
            
            <div dangerouslySetInnerHTML={{__html: MainScript}} />
        </body>
    </html>
)};

// =======================
// 4. MAIN ROUTES
// =======================
app.get("/", async (c) => {
    const session = await getSessionUser(c);
    const maintenance = await isMaintenanceMode();
    if (maintenance && session?.user.username !== ADMIN_USERNAME) return c.html(<Layout><div class="text-center mt-32 text-yellow-500"><i class="fa-solid fa-screwdriver-wrench text-4xl"></i><h1 class="text-2xl font-bold mt-4">ပြုပြင်နေပါသည် (Maintenance)</h1></div></Layout>);
    if(!session) return c.redirect("/login");
    const { user, csrfToken } = session;
    if(user.isBanned) return c.text("အကောင့် ပိတ်ထားခံရပါသည်", 403);

    const filterType = c.req.query('type') || 'all';
    const searchQuery = c.req.query('q')?.toLowerCase();
    
    // Fetch Files (Since Key includes timestamp, reverse:true makes newest first)
    const files = [];
    const fIter = kv.list<FileData>({ prefix: ["files", user.username] }, { reverse: true, limit: 100 });
    for await (const res of fIter) { 
        if(searchQuery) { if(res.value.name.toLowerCase().includes(searchQuery)) files.push(res.value); } 
        else if (filterType === 'all' || res.value.type === filterType) files.push(res.value); 
    }

    // Fetch Active Jobs
    const activeJobs = [];
    const jIter = kv.list<JobData>({ prefix: ["jobs", user.username] });
    for await (const res of jIter) {
        if(res.value.status === 'pending' || res.value.status === 'processing') activeJobs.push(res.value.id);
    }

    const totalGB = (user.usedStorage / 1024**3).toFixed(2);
    const limitGB = (PLANS[user.plan].limit / 1024**3).toFixed(0);
    const usedPercent = Math.min(100, (user.usedStorage / PLANS[user.plan].limit) * 100);

    return c.html(<Layout user={user} csrfToken={csrfToken} activeJobs={activeJobs}>
        {/* Dashboard */}
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
            <div class="glass p-5 rounded-2xl">
                <p class="text-xs text-zinc-500 font-bold uppercase">လက်ရှိ အစီအစဉ်</p>
                <p class="text-2xl font-black text-yellow-500">{PLANS[user.plan].name}</p>
                <div class="mt-2 text-xs text-gray-400">User: <span class="text-white font-mono">{user.username}</span></div>
            </div>
            <div class="glass p-5 rounded-2xl">
                <div class="flex justify-between mb-1"><span class="text-xs font-bold text-zinc-500 uppercase">အသုံးပြုထားမှု</span><span class="text-white font-bold">{totalGB} / {limitGB} GB</span></div>
                <div class="w-full bg-zinc-800 rounded-full h-3"><div class="bg-gradient-to-r from-yellow-600 to-yellow-400 h-full rounded-full" style={`width: ${usedPercent}%`}></div></div>
            </div>
        </div>

        {/* Upload Area */}
        <div class="glass p-6 rounded-2xl mb-8 border border-zinc-700/50">
            <div class="flex gap-4 mb-6 border-b border-zinc-800 pb-4">
                <button id="btn-mode-local" onclick="switchUploadMode('local')" class="mode-btn px-4 py-2 text-xs font-bold rounded-lg bg-yellow-500 text-black flex gap-2"><i class="fa-solid fa-upload"></i> ဖိုင်တင်မည်</button>
                <button id="btn-mode-remote" onclick="switchUploadMode('remote')" class="mode-btn px-4 py-2 text-xs font-bold rounded-lg bg-zinc-800 text-gray-400 flex gap-2"><i class="fa-solid fa-globe"></i> လင့်ခ်ဖြင့်တင်မည်</button>
            </div>

            <div id="mode-local" class="upload-mode">
                <form id="uploadForm" onsubmit="uploadLocal(event)" class="space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <input name="customName" placeholder="ဖိုင်နာမည် (Optional)" class="bg-black border border-zinc-700 rounded-xl p-3 text-sm text-white w-full" />
                        {isVipActive(user) ? <select name="expiry" class="bg-black border border-yellow-600/50 rounded-xl p-3 text-sm text-yellow-500 w-full"><option value="0">သက်တမ်းမဲ့ (Lifetime)</option><option value="7">၇ ရက်</option><option value="30">၁ လ</option></select> : <input disabled value="၃၀ ရက် (Free Plan)" class="bg-zinc-900 border border-zinc-700 text-gray-500 rounded-xl p-3 text-sm w-full" />}
                    </div>
                    <div class="grid grid-cols-2 gap-4"><label class="cursor-pointer"><input type="radio" name="server" value="1" class="peer sr-only" checked /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-blue-500 text-center text-xs font-bold text-gray-400 peer-checked:text-white">Server 1</div></label><label class="cursor-pointer"><input type="radio" name="server" value="2" class="peer sr-only" /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-yellow-500 text-center text-xs font-bold text-gray-400 peer-checked:text-white">Server 2</div></label></div>
                    <div class="border-2 border-dashed border-zinc-800 rounded-2xl p-6 text-center hover:bg-zinc-900 relative cursor-pointer">
                        <input type="file" id="fileInput" class="absolute inset-0 opacity-0 cursor-pointer w-full h-full" />
                        <i class="fa-solid fa-plus text-2xl text-zinc-600 mb-2"></i><p id="fileNameDisplay" class="text-sm font-bold text-zinc-400">ဖိုင်ရွေးချယ်ရန် နှိပ်ပါ</p>
                    </div>
                    <div id="progressContainer" class="hidden"><div class="flex justify-between text-[10px] text-zinc-400 mb-1"><span>Uploading...</span><span id="progressText">0%</span></div><div class="w-full bg-zinc-800 rounded-full h-2"><div id="progressBar" class="bg-yellow-500 h-full rounded-full w-0"></div></div></div>
                    <button id="submitBtn" class="w-full bg-yellow-500 text-black font-bold py-3 rounded-xl">တင်မည်</button>
                </form>
            </div>

            <div id="mode-remote" class="upload-mode hidden">
                <form onsubmit="uploadRemote(event)" class="space-y-4">
                    <input id="remoteUrl" type="url" placeholder="https://example.com/video.mp4" class="w-full bg-black border border-zinc-700 rounded-xl p-3 text-sm text-white" />
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <input id="remoteName" placeholder="ဖိုင်နာမည် (Optional)" class="bg-black border border-zinc-700 rounded-xl p-3 text-sm text-white w-full" />
                        <select name="expiry_remote" class="bg-black border border-yellow-600/50 rounded-xl p-3 text-sm text-yellow-500 w-full"><option value="0">သက်တမ်းမဲ့ (Lifetime)</option><option value="7">၇ ရက်</option><option value="30">၁ လ</option></select>
                    </div>
                    <div class="grid grid-cols-3 gap-2">
                        <label class="cursor-pointer"><input type="radio" name="server_remote" value="1" class="peer sr-only" checked /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-blue-500 text-center text-[10px] font-bold text-gray-400 peer-checked:text-white">Server 1</div></label>
                        <label class="cursor-pointer"><input type="radio" name="server_remote" value="2" class="peer sr-only" /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-yellow-500 text-center text-[10px] font-bold text-gray-400 peer-checked:text-white">Server 2</div></label>
                        <label class="cursor-pointer"><input type="radio" name="server_remote" value="both" class="peer sr-only" /><div class="p-3 bg-black border border-zinc-700 rounded-xl peer-checked:border-purple-500 text-center text-[10px] font-bold text-gray-400 peer-checked:text-white">Both</div></label>
                    </div>
                    <button id="remoteBtn" class="w-full bg-zinc-800 text-white font-bold py-3 rounded-xl hover:bg-zinc-700">Remote Upload စတင်မည်</button>
                </form>
            </div>
        </div>

        {/* Job Container */}
        <div id="job-container" class={activeJobs.length > 0 ? "mb-8" : "mb-8 hidden"}></div>

        {/* File List Header */}
        <div class="flex flex-col md:flex-row justify-between items-center mb-4 gap-3">
            <h3 class="font-bold text-white uppercase text-sm"><i class="fa-solid fa-folder-open mr-2 text-yellow-500"></i> မိမိဖိုင်များ</h3>
            <div class="flex items-center gap-3 w-full md:w-auto">
                <div class="flex bg-zinc-900 rounded-lg p-1">
                    <a href="/?type=all" class={`px-3 py-1 text-[10px] font-bold rounded ${filterType==='all'?'bg-yellow-500 text-black':'text-gray-400'}`}>ALL</a>
                    <a href="/?type=video" class={`px-3 py-1 text-[10px] font-bold rounded ${filterType==='video'?'bg-yellow-500 text-black':'text-gray-400'}`}>VID</a>
                    <a href="/?type=image" class={`px-3 py-1 text-[10px] font-bold rounded ${filterType==='image'?'bg-yellow-500 text-black':'text-gray-400'}`}>IMG</a>
                </div>
                <button onclick="openDeleteAllModal()" class="text-[10px] bg-red-900/30 text-red-500 border border-red-900 px-3 py-1.5 rounded-lg hover:bg-red-600 hover:text-white transition font-bold whitespace-nowrap"><i class="fa-solid fa-dumpster-fire mr-1"></i> အားလုံးဖျက်မည်</button>
            </div>
        </div>
        
        {/* File List Grid */}
        <div class="grid grid-cols-1 gap-3">
            {files.map(f => (
                <div class="bg-zinc-900/50 p-3 rounded-xl border border-transparent hover:border-zinc-700 flex flex-col md:flex-row items-center justify-between gap-3 group">
                    <div class="flex items-center gap-3 overflow-hidden w-full">
                        <div class={`w-10 h-10 rounded-lg flex items-center justify-center text-lg shrink-0 ${f.type==='image'?'bg-yellow-900/20 text-yellow-500':'bg-blue-900/20 text-blue-500'}`}><i class={`fa-solid ${f.type==='image'?'fa-image':f.type==='video'?'fa-clapperboard':'fa-file'}`}></i></div>
                        <div class="min-w-0 w-full">
                            <a href={`/d/${f.server}/${f.r2Key}`} target="_blank" class="font-bold text-sm text-gray-200 truncate block hover:text-yellow-500">{f.name}</a>
                            <div class="flex flex-wrap gap-2 text-[10px] text-gray-500 mt-1">
                                <span class="bg-black px-1.5 rounded text-gray-400">{f.size}</span>
                                <span>{formatDate(f.uploadedAt)}</span>
                                <span class="text-zinc-600">|</span>
                                {f.expiresAt > 0 ? <span class="text-red-400">သက်တမ်း: {formatDate(f.expiresAt)}</span> : <span class="text-green-500">သက်တမ်းမဲ့</span>}
                            </div>
                        </div>
                    </div>
                    <div class="flex gap-2 w-full md:w-auto justify-end border-t border-zinc-800 pt-2 md:pt-0 md:border-0">
                        <button onclick={`navigator.clipboard.writeText(window.location.origin + '/d/${f.server}/${f.r2Key}'); showToast('Link ကူးယူပြီးပါပြီ!')`} class="px-3 py-1.5 bg-zinc-800 rounded-lg hover:bg-white hover:text-black text-gray-400 text-xs font-bold transition">Copy</button>
                        <a href={`/d/${f.server}/${f.r2Key}`} target="_blank" class="px-3 py-1.5 bg-zinc-800 rounded-lg hover:bg-blue-600 text-white text-xs font-bold transition flex items-center gap-1"><i class="fa-solid fa-play"></i> ကြည့်မည်</a>
                        <a href={`/dl/${f.server}/${f.r2Key}`} class="px-3 py-1.5 bg-zinc-800 rounded-lg hover:bg-green-600 text-white text-xs font-bold transition flex items-center gap-1"><i class="fa-solid fa-download"></i> ဒေါင်းမည်</a>
                        <button onclick={`openDeleteModal('${f.id}')`} class="w-8 h-8 flex items-center justify-center bg-zinc-800 rounded-lg hover:bg-red-600 text-white transition"><i class="fa-solid fa-trash text-xs"></i></button>
                    </div>
                </div>
            ))}
            {files.length===0 && <p class="text-center text-zinc-600 text-sm py-10">ဖိုင်များ မရှိသေးပါ</p>}
        </div>
    </Layout>);
});

// =======================
// 5. API & PROCESSING
// =======================

async function processRemoteUpload(jobId: string, user: User, url: string, customName: string, server: string, expiry: string) {
    const jobKey = ["jobs", user.username, jobId];
    try {
        const res = await fetch(url);
        if(!res.ok) throw new Error(`Fetch Failed: ${res.status}`);
        const totalSize = parseInt(res.headers.get("content-length") || "0");
        const type = res.headers.get("content-type") || "application/octet-stream";
        
        if(totalSize > MAX_REMOTE_SIZE) throw new Error("ဖိုင်ဆိုဒ် ကြီးလွန်းပါသည် (>2GB)");
        if(user.usedStorage + (server === 'both' ? totalSize*2 : totalSize) > PLANS[user.plan].limit) throw new Error("Storage ပြည့်နေပါသည်");

        let ext = mimeToExt(type);
        if(BLOCKED_EXTENSIONS.has(ext)) throw new Error("ခွင့်မပြုသော ဖိုင်အမျိုးအစား");
        const safeName = (customName || "remote").replace(/[^a-zA-Z0-9.\-_\u1000-\u109F]/g, "_");
        const fileName = safeName.includes('.') ? safeName : `${safeName}.${ext}`;

        await kv.set(jobKey, { id: jobId, username: user.username, name: fileName, status: "processing", progress: 0, totalSize: (totalSize/1024**2).toFixed(1)+"MB", createdAt: Date.now() } as JobData);

        const doUpload = async (svr: "1" | "2", stream: ReadableStream) => {
            const client = svr === "1" ? s3Server1 : s3Server2;
            const bucket = svr === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
            // Reverse sorting trick: timestamp is first
            const r2Key = `${user.username}/${Date.now()}-${fileName}`;
            const fileId = `${Date.now()}-${crypto.randomUUID()}`;
            
            const upload = new Upload({
                client, params: { Bucket: bucket, Key: r2Key, Body: stream as any, ContentType: type },
                queueSize: 4, partSize: 10 * 1024 * 1024 
            });
            
            upload.on("httpUploadProgress", async (p) => {
                if(totalSize) {
                    const pct = Math.round((p.loaded! / totalSize) * 100);
                    if(pct % 5 === 0) {
                        const current = await kv.get<JobData>(jobKey);
                        if(current.value) await kv.set(jobKey, { ...current.value, progress: pct });
                    }
                }
            });

            await upload.done();
            return { fileId, r2Key, sizeBytes: totalSize };
        };

        let results = [];
        if(server === "both") {
            const [s1, s2] = res.body!.tee();
            results = await Promise.all([doUpload("1", s1), doUpload("2", s2)]);
        } else {
            results = [await doUpload(server as "1"|"2", res.body!)];
        }

        const expiryDays = parseInt(expiry) || 0;
        const now = Date.now();
        
        for(let i=0; i<results.length; i++) {
            const r = results[i];
            const svr = server === "both" ? (i===0?"1":"2") : server;
            const fData: FileData = { 
                id: r.fileId, name: fileName, sizeBytes: r.sizeBytes, size: (r.sizeBytes/1024**2).toFixed(2)+" MB", 
                server: svr as any, r2Key: r.r2Key, uploadedAt: now, expiresAt: expiryDays > 0 ? now + (expiryDays*86400000) : 0, 
                type: type.startsWith("image") ? "image" : type.startsWith("video") ? "video" : "other", isVipFile: true 
            };
            await kv.set(["files", user.username, r.fileId], fData);
        }

        const totalBytes = server === "both" ? totalSize * 2 : totalSize;
        const uRes = await kv.get<User>(["users", user.username]);
        if(uRes.value) await kv.set(["users", user.username], { ...uRes.value, usedStorage: uRes.value.usedStorage + totalBytes });
        await updateStats(totalBytes);

        await kv.set(jobKey, { ...((await kv.get(jobKey)).value as JobData), status: "completed", progress: 100 });
        setTimeout(() => kv.delete(jobKey), 10000);

    } catch (e: any) {
        await kv.set(jobKey, { id: jobId, username: user.username, name: "Error", status: "failed", progress: 0, totalSize: "0", error: e.message, createdAt: Date.now() });
        setTimeout(() => kv.delete(jobKey), 30000);
    }
}

app.post("/api/upload/remote", async (c) => {
    if(!await checkRateLimit(c, "upload_remote", 5)) return c.json({error: "ခဏစောင့်ပါ (Rate Limit)"}, 429);
    const session = await getSessionUser(c);
    if(!session || !isVipActive(session.user)) return c.json({error: "VIP Only"}, 403);
    const { url, customName, server, expiry, csrf } = await c.req.json();
    if(csrf !== session.csrfToken) return c.json({error: "Invalid CSRF"}, 403);
    if (!isValidRemoteUrl(url)) return c.json({ error: "Invalid URL" }, 400);

    const jobId = crypto.randomUUID();
    const jobData: JobData = { id: jobId, username: session.user.username, name: "Pending...", status: "pending", progress: 0, totalSize: "...", createdAt: Date.now() };
    
    await kv.set(["jobs", session.user.username, jobId], jobData);
    processRemoteUpload(jobId, session.user, url, customName, server, expiry);

    return c.json({ success: true, jobId });
});

app.get("/api/job/:id", async (c) => {
    const session = await getSessionUser(c);
    if(!session) return c.json({error: "Auth"}, 401);
    const id = c.req.param("id");
    const res = await kv.get<JobData>(["jobs", session.user.username, id]);
    if(!res.value) return c.json({error: "Job not found"});
    return c.json(res.value);
});

app.post("/api/upload/presign", async (c) => {
    if(!await checkRateLimit(c, "upload_init", 10)) return c.json({error: "Rate Limit"}, 429);
    const session = await getSessionUser(c); if(!session) return c.json({error: "Auth"}, 401);
    const { name, size, server, type, customName, csrf } = await c.req.json();
    if(csrf !== session.csrfToken) return c.json({error: "CSRF"}, 403);
    
    const limit = PLANS[session.user.plan].limit;
    if (session.user.usedStorage + size > limit) return c.json({ error: "Storage ပြည့်နေပါသည်" }, 400);
    
    const nCheck = validateFileName(name);
    if(!nCheck.valid) return c.json({error: nCheck.error}, 400);

    const finalName = customName ? (customName.endsWith('.'+nCheck.ext) ? customName : customName+'.'+nCheck.ext) : name;
    const safeName = finalName.replace(/[^a-zA-Z0-9.\-_\u1000-\u109F]/g, "_");
    const r2Key = `${session.user.username}/${Date.now()}-${safeName}`; // Timestamp first for sorting
    
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    const url = await getSignedUrl(client, new PutObjectCommand({ Bucket: bucket, Key: r2Key, ContentType: type }), { expiresIn: 3600 });
    return c.json({ url, key: r2Key, fileId: `${Date.now()}-${crypto.randomUUID()}` });
});

app.post("/api/upload/complete", async (c) => {
    const session = await getSessionUser(c); if(!session) return c.json({error:"Auth"},401);
    const { key, fileId, server, expiry } = await c.req.json();
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    try {
        const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
        const size = head.ContentLength || 0;
        // Clean name retrieval
        const nameParts = key.split('/');
        const rawName = nameParts[nameParts.length - 1]; 
        const name = rawName.substring(rawName.indexOf('-') + 1); // remove timestamp prefix

        const type = head.ContentType?.startsWith("image") ? "image" : head.ContentType?.startsWith("video") ? "video" : "other";
        
        const uRes = await kv.get<User>(["users", session.user.username]);
        if(uRes.value) {
            await kv.set(["users", session.user.username], {...uRes.value, usedStorage: uRes.value.usedStorage + size});
            const exp = isVipActive(session.user) ? (parseInt(expiry)||0) : 30;
            const fData: FileData = { id: fileId, name, sizeBytes: size, size: (size/1024**2).toFixed(2)+" MB", server, r2Key: key, uploadedAt: Date.now(), expiresAt: exp>0?Date.now()+(exp*86400000):0, type, isVipFile: isVipActive(session.user) };
            await kv.set(["files", session.user.username, fileId], fData);
            await updateStats(size);
        }
        return c.json({success:true});
    } catch { return c.json({error:"Failed"}, 500); }
});

// Single File Delete
app.post("/delete/:id", async (c) => {
    const session = await getSessionUser(c); if(!session) return c.redirect("/login");
    const { csrf } = await c.req.parseBody(); if(csrf !== session.csrfToken) return c.text("CSRF Fail", 403);
    const id = c.req.param("id");
    const fRes = await kv.get<FileData>(["files", session.user.username, id]);
    if(fRes.value) {
        const f = fRes.value;
        const client = f.server === "1" ? s3Server1 : s3Server2;
        const bucket = f.server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
        try { await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: f.r2Key })); } catch {}
        await kv.delete(["files", session.user.username, id]);
        const uRes = await kv.get<User>(["users", session.user.username]);
        if(uRes.value) await kv.set(["users", session.user.username], {...uRes.value, usedStorage: Math.max(0, uRes.value.usedStorage - f.sizeBytes)});
        await updateStats(-f.sizeBytes);
    }
    return c.redirect("/");
});

// Delete ALL Files
app.post("/api/delete-all", async (c) => {
    const session = await getSessionUser(c); if(!session) return c.json({error:"Auth"}, 401);
    const { csrf } = await c.req.parseBody(); if(csrf !== session.csrfToken) return c.json({error:"CSRF"}, 403);
    
    const iter = kv.list<FileData>({ prefix: ["files", session.user.username] });
    let totalFreed = 0;
    
    for await (const res of iter) {
        const f = res.value;
        const client = f.server === "1" ? s3Server1 : s3Server2;
        const bucket = f.server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
        try { await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: f.r2Key })); } catch {}
        await kv.delete(res.key);
        totalFreed += f.sizeBytes;
    }

    const uRes = await kv.get<User>(["users", session.user.username]);
    if(uRes.value) await kv.set(["users", session.user.username], {...uRes.value, usedStorage: 0});
    await updateStats(-totalFreed);
    
    return c.redirect("/");
});

// View Link (Inline)
app.get("/d/:server/*", async (c) => {
    const server = c.req.param("server");
    const key = c.req.path.split(`/d/${server}/`)[1];
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    try {
        const url = await getSignedUrl(client, new GetObjectCommand({ Bucket: bucket, Key: key, ResponseContentDisposition: "inline" }), { expiresIn: 3600 });
        return c.redirect(url);
    } catch { return c.text("File Not Found", 404); }
});

// Download Link (Attachment)
app.get("/dl/:server/*", async (c) => {
    const server = c.req.param("server");
    const key = c.req.path.split(`/dl/${server}/`)[1];
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    try {
        const url = await getSignedUrl(client, new GetObjectCommand({ Bucket: bucket, Key: key, ResponseContentDisposition: "attachment" }), { expiresIn: 3600 });
        return c.redirect(url);
    } catch { return c.text("File Not Found", 404); }
});

// Auth Routes
app.get("/login", (c) => c.html(<Layout hideLoginLink={true}><div class="max-w-sm mx-auto mt-24 glass p-8 rounded-2xl"><h1 class="text-2xl font-black text-center text-yellow-500 mb-6">LOGIN</h1><form action="/login" method="post" class="space-y-4"><input name="username" placeholder="Username" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white"/><input type="password" name="password" placeholder="Password" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white"/><button class="w-full bg-yellow-500 font-bold py-3 rounded-xl">ဝင်မည်</button></form><div class="text-center mt-4"><a href="/register" class="text-xs text-gray-500 hover:text-white">အကောင့်သစ် ဖွင့်မည်</a></div></div></Layout>));
app.post("/login", async (c) => {
    if(!await checkRateLimit(c, "login", 5)) return c.text("Rate Limit", 429);
    const { username, password } = await c.req.parseBody();
    const uRes = await kv.get<User>(["users", String(username)]);
    if(uRes.value && uRes.value.passwordHash === await hashPassword(String(password))) { await createSession(c, String(username)); return c.redirect("/"); }
    return c.html("Login Failed. Back to <a href='/login'>Login</a>");
});
app.get("/register", (c) => c.html(<Layout hideLoginLink={true}><div class="max-w-sm mx-auto mt-24 glass p-8 rounded-2xl"><h1 class="text-2xl font-black text-center text-white mb-6">REGISTER</h1><form action="/register" method="post" class="space-y-4"><input name="username" placeholder="Username" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white"/><input type="password" name="password" placeholder="Password (Min 6)" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white"/><button class="w-full bg-green-600 font-bold py-3 rounded-xl text-white">စာရင်းသွင်းမည်</button></form></div></Layout>));
app.post("/register", async (c) => {
    if(!await checkRateLimit(c, "register", 3)) return c.text("Rate Limit", 429);
    const { username, password } = await c.req.parseBody();
    const u = String(username).replace(/[^a-zA-Z0-9]/g,"");
    if(u.length<3 || String(password).length<6) return c.text("Invalid Input");
    const uKey = ["users", u];
    const res = await kv.atomic().check({key:uKey, versionstamp:null}).set(uKey, { username: u, passwordHash: await hashPassword(String(password)), plan: 'free', isVip: false, usedStorage: 0, createdAt: Date.now() }).commit();
    if(res.ok) { await incrementUserCount(); return c.redirect("/login"); }
    return c.text("Username Taken");
});
app.get("/logout", (c) => { deleteCookie(c, "session_id"); return c.redirect("/login"); });

// Cleanup Job
Deno.cron("Cleanup", "0 * * * *", async () => {
    const now = Date.now();
    for await (const entry of kv.list<FileData>({ prefix: ["files"] })) {
        const f = entry.value; const uRes = await kv.get<User>(["users", entry.key[1] as string]);
        if (uRes.value) {
            const u = uRes.value;
            if ((f.expiresAt > 0 && f.expiresAt < now) || (u.vipExpiry && u.vipExpiry < now && now > u.vipExpiry + 604800000)) {
                try {
                    const client = f.server==="1"?s3Server1:s3Server2;
                    const bucket = f.server==="1"?Deno.env.get("R2_1_BUCKET_NAME"):Deno.env.get("R2_2_BUCKET_NAME");
                    await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: f.r2Key }));
                } catch {}
                await kv.delete(entry.key);
                await kv.set(["users", u.username], {...u, usedStorage: Math.max(0, u.usedStorage - f.sizeBytes)});
                await updateStats(-f.sizeBytes);
            }
        }
    }
});

Deno.serve(app.fetch);
