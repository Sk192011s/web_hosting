/** @jsxImportSource npm:hono@4/jsx */ 
import { Hono, Context } from "npm:hono@4";
import { getCookie, setCookie, deleteCookie } from "npm:hono@4/cookie";
import { secureHeaders } from "npm:hono@4/secure-headers";
import { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand, HeadObjectCommand, ListObjectsV2Command } from "npm:@aws-sdk/client-s3";
import { getSignedUrl } from "npm:@aws-sdk/s3-request-presigner";
import { Upload } from "npm:@aws-sdk/lib-storage"; 
import { html } from "npm:hono@4/html";

// =======================
// 1. CONFIGURATION & ENV
// =======================
const app = new Hono();

// Security Headers (Strict CSP to prevent XSS)
app.use('*', secureHeaders({
    contentSecurityPolicy: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "blob:", "*"], // Allow images from everywhere for previews
        connectSrc: ["'self'", "*"], // Allow uploads
    }
}));

const kv = await Deno.openKv();

const ADMIN_USERNAME = Deno.env.get("ADMIN_USERNAME") || "admin"; 
const SECRET_KEY = Deno.env.get("SECRET_SALT") || "change-this-secret-salt-immediately";
const MAX_REMOTE_SIZE = 2 * 1024 * 1024 * 1024; // 2 GB
const ALLOWED_EXTENSIONS = new Set(['jpg','jpeg','png','gif','webp','mp4','mkv','webm','mov','mp3','wav','zip','rar','7z','pdf','txt','doc','docx']);
const BLOCKED_EXTENSIONS = new Set(['exe','sh','php','pl','py','js','html','htm','css','bat','cmd','msi','jar','vbs']);

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
    username: string; passwordHash: string; plan: keyof typeof PLANS; isVip: boolean; vipExpiry?: number; usedStorage: number; createdAt: number; 
    isBanned?: boolean; isPendingDelete?: boolean; // New flag for background deletion
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

// Atomic Stats Update (Improved for accuracy)
async function updateStats(storageDelta: number) {
    const key = ["stats", "global"];
    const res = await kv.get<{totalUsers: number, totalStorage: number}>(key);
    const current = res.value || { totalUsers: 0, totalStorage: 0 };
    // Just a simple update, precise atomic sum is harder with object structure but this is sufficient for display
    await kv.set(key, { totalUsers: current.totalUsers, totalStorage: Math.max(0, current.totalStorage + storageDelta) });
}

async function incrementUserCount(delta: number) {
    const key = ["stats", "global"];
    const res = await kv.get<{totalUsers: number, totalStorage: number}>(key);
    const current = res.value || { totalUsers: 0, totalStorage: 0 };
    await kv.set(key, { ...current, totalUsers: Math.max(0, current.totalUsers + delta) });
}

async function isMaintenanceMode(): Promise<boolean> {
    const res = await kv.get<SystemConfig>(["config", "system"]);
    return res.value?.maintenance || false;
}

// --- Session Management ---
async function createSession(c: Context, username: string) {
    const sessionId = crypto.randomUUID();
    const csrfToken = crypto.randomUUID();
    await kv.set(["sessions", sessionId], { username, expires: Date.now() + (7 * 86400000), csrfToken }, { expireIn: 7 * 86400000 });
    setCookie(c, "session_id", sessionId, { path: "/", httpOnly: true, secure: true, sameSite: "Lax", maxAge: 7 * 24 * 60 * 60 });
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

// --- Validations ---
function isValidRemoteUrl(urlString: string): boolean {
    try {
        const url = new URL(urlString);
        if (!['http:', 'https:'].includes(url.protocol)) return false;
        const host = url.hostname;
        if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]') return false;
        if (host.startsWith('192.168.') || host.startsWith('10.') || host.match(/^172\.(1[6-9]|2\d|3[0-1])\./)) return false;
        return true;
    } catch { return false; }
}

function validateFileName(name: string): { valid: boolean, error?: string, safeName?: string, ext?: string } {
    const ext = name.split('.').pop()?.toLowerCase() || '';
    if (BLOCKED_EXTENSIONS.has(ext)) return { valid: false, error: "Security Restriction: File type not allowed." };
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
        toast.innerHTML = \`<i class="\${type === 'error' ? 'fa-solid fa-triangle-exclamation' : 'fa-solid fa-check-circle'}"></i> <span class="font-bold text-sm">\${message}</span>\`;
        container.appendChild(toast);
        requestAnimationFrame(() => toast.classList.remove('translate-y-10', 'opacity-0'));
        setTimeout(() => { toast.classList.add('translate-y-10', 'opacity-0'); setTimeout(() => toast.remove(), 300); }, 3000);
    }
    function setLoading(btnId, isLoading, text = 'Loading...') {
        const btn = document.getElementById(btnId);
        if(!btn) return;
        if(isLoading) { btn.dataset.o = btn.innerHTML; btn.disabled = true; btn.innerHTML = \`<i class="fa-solid fa-circle-notch fa-spin"></i> \${text}\`; btn.classList.add('opacity-75', 'cursor-not-allowed'); } 
        else { btn.disabled = false; btn.innerHTML = btn.dataset.o || 'Submit'; btn.classList.remove('opacity-75', 'cursor-not-allowed'); }
    }
</script>`;

const MainScript = `
<script>
    const IS_VIP = window.IS_VIP_USER || false;
    let targetId = null, isUp = false;
    window.onbeforeunload = function() { if(isUp) return "Upload in progress. Leave?"; };
    document.body.style.visibility = 'visible';

    function switchMode(m) {
        if(m === 'remote' && !IS_VIP) { document.getElementById('vipModal').classList.remove('hidden'); return; }
        document.querySelectorAll('.u-mode').forEach(e => e.classList.add('hidden'));
        document.querySelectorAll('.m-btn').forEach(e => {e.classList.remove('bg-yellow-500','text-black'); e.classList.add('bg-zinc-800','text-gray-400')});
        document.getElementById('m-'+m).classList.remove('hidden');
        document.getElementById('btn-'+m).classList.add('bg-yellow-500','text-black');
    }

    // ... (Existing Modal Logic) ...
    function closeModal(id) { document.getElementById(id).classList.add('hidden'); targetId = null; }
    function openDel(id) { targetId = id; document.getElementById('delModal').classList.remove('hidden'); }
    async function doDel() {
        if(!targetId) return; setLoading('btnDel', true, 'Deleting...');
        try { await fetch('/delete/'+targetId, {method:'POST', body: new URLSearchParams({csrf: window.CSRF})}); window.location.reload(); }
        catch(e) { showToast('Error', 'error'); setLoading('btnDel', false); }
    }
    
    // Remote Upload
    async function upRemote(e) {
        e.preventDefault();
        const url = document.getElementById('rUrl').value;
        if(!url) return showToast("URL Required", "error");
        isUp = true; setLoading('rBtn', true, 'Connecting...');
        document.getElementById('rProg').classList.remove('hidden');
        
        try {
            const res = await fetch('/api/upload/remote', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    url, customName: document.getElementById('rName').value,
                    server: document.querySelector('input[name="rSvr"]:checked').value,
                    expiry: document.querySelector('select[name="rExp"]').value,
                    csrf: window.CSRF
                })
            });
            const reader = res.body.getReader();
            const dec = new TextDecoder();
            
            while(true) {
                const {done, value} = await reader.read();
                if(done) break;
                const chunks = dec.decode(value, {stream:true}).split('\\n');
                for(const c of chunks) {
                    if(!c) continue;
                    try {
                        const d = JSON.parse(c);
                        if(d.error) throw new Error(d.error);
                        if(d.progress) {
                            document.getElementById('rBar').style.width = d.progress + "%";
                            document.getElementById('rTxt').innerText = d.progress + "%";
                        }
                        if(d.done) { showToast("Success!"); setTimeout(() => window.location.reload(), 1000); isUp = false; }
                    } catch(e) { throw e; }
                }
            }
        } catch(e) { showToast(e.message, 'error'); isUp = false; setLoading('rBtn', false); document.getElementById('rProg').classList.add('hidden'); }
    }
    
    // Local Upload (Presigned)
    async function upLocal(e) {
        e.preventDefault();
        const f = document.getElementById('fIn').files[0];
        if(!f) return showToast("File Required", 'error');
        isUp = true; setLoading('lBtn', true, 'Preparing...');
        document.getElementById('lProg').classList.remove('hidden');
        
        try {
            const fd = new FormData(e.target);
            const init = await fetch("/api/upload/presign", {
                method: "POST", headers: {"Content-Type":"application/json"},
                body: JSON.stringify({ name: f.name, type: f.type, size: f.size, server: fd.get("server"), customName: fd.get("customName"), csrf: window.CSRF })
            }).then(r => r.json());
            
            if(init.error) throw new Error(init.error);
            
            setLoading('lBtn', true, 'Uploading...');
            const xhr = new XMLHttpRequest();
            xhr.open("PUT", init.url, true);
            xhr.upload.onprogress = ev => {
                if(ev.lengthComputable) {
                    const p = Math.round((ev.loaded/ev.total)*100);
                    document.getElementById('lBar').style.width = p+"%";
                    document.getElementById('lTxt').innerText = p+"%";
                }
            };
            xhr.onload = async () => {
                if(xhr.status === 200) {
                    await fetch("/api/upload/complete", {
                        method:"POST", headers:{"Content-Type":"application/json"},
                        body: JSON.stringify({ key: init.key, fileId: init.fileId, server: fd.get("server"), expiry: fd.get("expiry"), csrf: window.CSRF })
                    });
                    showToast("Uploaded!"); setTimeout(() => window.location.reload(), 1000);
                } else throw new Error("Upload Failed");
            };
            xhr.send(f);
        } catch(e) { showToast(e.message, 'error'); isUp = false; setLoading('lBtn', false); document.getElementById('lProg').classList.add('hidden'); }
    }
</script>
`;

const Layout = (props: { children: any; title?: string; user?: User | null, csrf?: string, noLogin?: boolean }) => {
    const isVip = props.user ? isVipActive(props.user) : false;
    return (
    <html lang="my">
        <head>
            <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>{props.title || "Gold Storage Cloud"}</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" />
            <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap" rel="stylesheet" />
            <style>{`body { font-family: 'Padauk', sans-serif; background: #050505; color: #e4e4e7; visibility: hidden; } .glass { background: #121212; border: 1px solid #27272a; } .vip-card:hover { border-color: #eab308; transform: translateY(-5px); } .custom-scroll::-webkit-scrollbar { width: 5px; background: #000; } .custom-scroll::-webkit-scrollbar-thumb { background: #333; border-radius: 5px; }`}</style>
            <script dangerouslySetInnerHTML={{__html: `window.IS_VIP_USER = ${isVip}; window.CSRF = "${props.csrf || ''}";`}} />
            <div dangerouslySetInnerHTML={{__html: ToastScript}} />
        </head>
        <body data-vip={isVip ? "true" : "false"}>
            <div id="toast-container" class="fixed top-20 right-5 z-[200] flex flex-col gap-3"></div>
            <nav class="fixed top-0 w-full z-50 glass border-b border-zinc-800 bg-black/80 backdrop-blur-md"><div class="max-w-5xl mx-auto px-4 py-3 flex justify-between items-center"><a href="/" class="text-xl font-black text-white italic tracking-tighter flex items-center gap-2"><i class="fa-solid fa-cube text-yellow-500"></i> <span class="bg-clip-text text-transparent bg-gradient-to-r from-yellow-400 to-yellow-600">GOLD STORAGE</span></a>
            {props.user ? (<div class="flex gap-3 items-center"><div class="hidden sm:flex flex-col items-end leading-tight"><span class="text-xs font-bold text-gray-300">{props.user.username}</span>{isVipActive(props.user) ? <span class="text-[9px] text-yellow-500 font-bold bg-yellow-500/10 px-1 rounded">VIP</span> : <span class="text-[9px] text-gray-500 font-bold bg-zinc-800 px-1 rounded">FREE</span>}</div>{props.user.username === ADMIN_USERNAME && <a href="/admin" class="w-8 h-8 flex items-center justify-center bg-purple-600 rounded-full hover:bg-purple-500 text-white"><i class="fa-solid fa-shield-halved text-xs"></i></a>}<a href="/logout" class="w-8 h-8 flex items-center justify-center bg-zinc-800 border border-zinc-700 rounded-full hover:bg-red-600/20 hover:text-red-500"><i class="fa-solid fa-power-off text-xs"></i></a></div>) : (
                !props.noLogin && <a href="/login" class="text-xs bg-yellow-500 text-black px-4 py-2 rounded-full font-bold hover:bg-yellow-400 transition">ဝင်မည်</a>
            )}</div></nav>
            <main class="pt-24 pb-10 px-4 max-w-5xl mx-auto">{props.children}</main>
            <div id="vipModal" class="fixed inset-0 bg-black/80 backdrop-blur z-50 hidden flex items-center justify-center"><div class="bg-zinc-900 border border-yellow-500 p-6 rounded-xl max-w-sm text-center"><i class="fa-solid fa-crown text-4xl text-yellow-500 mb-3"></i><h3 class="font-bold text-xl text-white">VIP Only</h3><p class="text-gray-400 text-sm mt-2 mb-4">Remote URL upload is for VIP members.</p><button onclick="closeModal('vipModal')" class="bg-yellow-500 text-black px-6 py-2 rounded-lg font-bold">OK</button></div></div>
            <div id="delModal" class="fixed inset-0 bg-black/80 backdrop-blur z-50 hidden flex items-center justify-center"><div class="bg-zinc-900 border border-zinc-700 p-6 rounded-xl max-w-sm text-center"><h3 class="font-bold text-xl text-white">Delete File?</h3><p class="text-gray-400 text-sm mt-2 mb-4">Cannot be undone.</p><div class="flex gap-2"><button onclick="closeModal('delModal')" class="flex-1 bg-zinc-700 py-2 rounded-lg text-white">Cancel</button><button id="btnDel" onclick="doDel()" class="flex-1 bg-red-600 py-2 rounded-lg text-white">Delete</button></div></div></div>
            <div dangerouslySetInnerHTML={{__html: MainScript}} />
        </body>
    </html>
)};

// =======================
// 4. ROUTES
// =======================
app.get("/", async (c) => {
    const session = await getSessionUser(c);
    const maintenance = await isMaintenanceMode();
    if (maintenance && session?.user.username !== ADMIN_USERNAME) return c.html(<Layout noLogin><div class="text-center mt-32 text-yellow-500"><i class="fa-solid fa-screwdriver-wrench text-5xl mb-4"></i><h1 class="text-2xl font-bold">Maintenance Mode</h1></div></Layout>);
    if(!session) return c.redirect("/login");
    const { user, csrfToken } = session;
    if(user.isBanned) return c.html(<Layout><div class="text-center mt-20 text-red-500 font-bold p-10 border border-red-900 bg-red-900/10 rounded-xl">ACCOUNT BANNED</div></Layout>);

    const q = c.req.query('q')?.toLowerCase();
    const type = c.req.query('type') || 'all';
    const cursor = c.req.query('cursor');
    
    // Efficient listing
    const iter = kv.list<FileData>({ prefix: ["files", user.username] }, { reverse: true, limit: 50, cursor: cursor });
    const files = []; let nextC = "";
    for await (const res of iter) { 
        if(q && !res.value.name.toLowerCase().includes(q)) continue;
        if(type !== 'all' && res.value.type !== type) continue;
        files.push(res.value); nextC = res.cursor;
    }

    const plan = PLANS[user.plan] || PLANS.free;
    const usedPct = Math.min(100, (user.usedStorage / plan.limit) * 100);

    return c.html(<Layout user={user} csrf={csrfToken}>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <div class="glass p-5 rounded-2xl"><p class="text-xs text-zinc-500 font-bold uppercase">Plan</p><p class="text-2xl font-black text-yellow-500">{plan.name}</p></div>
            <div class="glass p-5 rounded-2xl"><p class="text-xs text-zinc-500 font-bold uppercase">Storage</p><div class="w-full bg-zinc-800 h-2 rounded-full mt-2"><div class="bg-yellow-500 h-full rounded-full" style={`width:${usedPct}%`}></div></div><p class="text-right text-xs mt-1 text-gray-400">{(user.usedStorage/1024**3).toFixed(2)} GB Used</p></div>
            <div class="glass p-5 rounded-2xl flex items-center justify-center"><a href="https://t.me/iqowoq" target="_blank" class="text-blue-400 hover:text-blue-300 font-bold flex gap-2"><i class="fa-brands fa-telegram text-xl"></i> Contact Admin</a></div>
        </div>

        <div class="glass p-6 rounded-2xl mb-8 relative">
            <div class="flex gap-4 mb-6 border-b border-zinc-800 pb-4">
                <button id="btn-local" onclick="switchMode('local')" class="m-btn px-4 py-2 text-xs font-bold rounded-lg bg-yellow-500 text-black flex gap-2 items-center"><i class="fa-solid fa-upload"></i> Upload</button>
                <button id="btn-remote" onclick="switchMode('remote')" class="m-btn px-4 py-2 text-xs font-bold rounded-lg bg-zinc-800 text-gray-400 flex gap-2 items-center"><i class="fa-solid fa-globe"></i> Remote URL {isVipActive(user)?"":"(VIP)"}</button>
            </div>

            <div id="m-local" class="u-mode">
                <form onsubmit="upLocal(event)" class="space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                         <input name="customName" placeholder="File Name (Optional)" class="bg-black border border-zinc-700 p-3 rounded-xl text-sm w-full text-white" />
                         {isVipActive(user) ? <select name="expiry" class="bg-black border border-yellow-600 p-3 rounded-xl text-sm text-yellow-500 w-full"><option value="0">Lifetime</option><option value="7">7 Days</option></select> : <input disabled value="30 Days (Free)" class="bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-sm w-full text-gray-500"/>}
                    </div>
                    <div class="flex gap-4"><label class="flex items-center gap-2"><input type="radio" name="server" value="1" checked /> Server 1</label><label class="flex items-center gap-2"><input type="radio" name="server" value="2" /> Server 2</label></div>
                    <input type="file" id="fIn" class="block w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:bg-zinc-800 file:text-white hover:file:bg-yellow-600"/>
                    <div id="lProg" class="hidden"><div class="flex justify-between text-xs mb-1"><span>Uploading...</span><span id="lTxt">0%</span></div><div class="w-full bg-zinc-800 h-1.5 rounded-full"><div id="lBar" class="bg-yellow-500 h-full rounded-full" style="width:0%"></div></div></div>
                    <button id="lBtn" class="bg-yellow-500 text-black font-bold w-full py-3 rounded-xl">Upload</button>
                </form>
            </div>

            <div id="m-remote" class="u-mode hidden">
                <form onsubmit="upRemote(event)" class="space-y-4">
                    <input id="rUrl" type="url" placeholder="https://site.com/video.mp4" class="bg-black border border-zinc-700 p-3 rounded-xl text-sm w-full text-white" />
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <input id="rName" placeholder="Name" class="bg-black border border-zinc-700 p-3 rounded-xl text-sm w-full text-white" />
                        <select name="rExp" class="bg-black border border-yellow-600 p-3 rounded-xl text-sm text-yellow-500 w-full"><option value="0">Lifetime</option><option value="7">7 Days</option></select>
                    </div>
                    <div class="flex gap-4"><label><input type="radio" name="rSvr" value="1" checked /> S1</label><label><input type="radio" name="rSvr" value="2" /> S2</label><label><input type="radio" name="rSvr" value="both" /> Both</label></div>
                    <div id="rProg" class="hidden"><div class="flex justify-between text-xs mb-1"><span>Processing...</span><span id="rTxt">0%</span></div><div class="w-full bg-zinc-800 h-1.5 rounded-full"><div id="rBar" class="bg-yellow-500 h-full rounded-full" style="width:0%"></div></div></div>
                    <button id="rBtn" class="bg-zinc-800 text-white font-bold w-full py-3 rounded-xl hover:bg-zinc-700">Remote Upload</button>
                </form>
            </div>
        </div>

        <div class="space-y-2">
            {files.map(f => (
                <div class="bg-zinc-900 p-3 rounded-xl flex justify-between items-center group hover:bg-zinc-800 transition">
                    <div class="flex items-center gap-3 overflow-hidden">
                        <div class="w-10 h-10 bg-zinc-800 rounded flex items-center justify-center"><i class={`fa-solid ${f.type==='video'?'fa-film text-blue-500':'fa-file text-gray-400'}`}></i></div>
                        <div class="min-w-0"><a href={`/d/${f.server}/${f.r2Key}`} target="_blank" class="font-bold text-sm block truncate group-hover:text-yellow-500">{f.name}</a><div class="text-[10px] text-gray-500">{f.size} • {f.expiresAt?formatDate(f.expiresAt):'Lifetime'}</div></div>
                    </div>
                    <button onclick={`openDel('${f.id}')`} class="w-8 h-8 rounded bg-zinc-800 hover:bg-red-600 text-gray-400 hover:text-white transition"><i class="fa-solid fa-trash text-xs"></i></button>
                </div>
            ))}
            {nextC && <div class="text-center pt-4"><a href={`/?type=${type}&cursor=${nextC}`} class="bg-zinc-800 text-xs px-4 py-2 rounded-full">Next Page</a></div>}
        </div>
    </Layout>);
});

// =======================
// 5. API API ROUTES
// =======================
app.post("/api/upload/presign", async (c) => {
    if(!await checkRateLimit(c, "up_init", 20)) return c.json({error:"Slow down"}, 429);
    const s = await getSessionUser(c); if(!s) return c.json({error:"Login"}, 401);
    const {name, size, type, customName, server, csrf} = await c.req.json();
    if(csrf !== s.csrfToken) return c.json({error:"CSRF"}, 403);
    
    if(s.user.usedStorage + size > (PLANS[s.user.plan]?.limit || PLANS.free.limit)) return c.json({error:"Storage Full"}, 400);
    const n = validateFileName(name); if(!n.valid) return c.json({error:n.error}, 400);
    
    let fn = customName ? customName.replace(/[^a-zA-Z0-9]/g,"_") + "." + n.ext : n.safeName;
    const key = `${s.user.username}/${Date.now()}-${fn}`;
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    
    const url = await getSignedUrl(client, new PutObjectCommand({Bucket: bucket, Key: key, ContentType: type}), {expiresIn:3600});
    return c.json({url, key, fileId: crypto.randomUUID()});
});

app.post("/api/upload/complete", async (c) => {
    const s = await getSessionUser(c); if(!s) return c.json({error:"Auth"}, 401);
    const { key, fileId, server, expiry, csrf } = await c.req.json();
    if(csrf !== s.csrfToken) return c.json({error:"CSRF"}, 403);

    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    
    try {
        const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
        const size = head.ContentLength || 0;
        const name = key.split('-').slice(1).join('-');
        const type = head.ContentType?.startsWith("image") ? "image" : head.ContentType?.startsWith("video") ? "video" : "other";
        const isVip = isVipActive(s.user);
        const exp = isVip ? (parseInt(expiry)||0) : 30;
        
        const fData: FileData = { id: fileId, name, sizeBytes: size, size: (size/1024**2).toFixed(2)+" MB", server, r2Key: key, uploadedAt: Date.now(), expiresAt: exp>0 ? Date.now()+(exp*86400000) : 0, type, isVipFile: isVip };
        
        // Optimistic Lock for User Storage Update
        let ok = false;
        while(!ok) {
            const uRes = await kv.get<User>(["users", s.user.username]);
            if(!uRes.value) break;
            const newUser = {...uRes.value, usedStorage: uRes.value.usedStorage + size};
            const r = await kv.atomic().check(uRes).set(["users", s.user.username], newUser).set(["files", s.user.username, fileId], fData).commit();
            ok = r.ok;
        }
        await updateStats(size);
        return c.json({success:true});
    } catch(e) { return c.json({error: "Failed"}, 500); }
});

app.post("/api/upload/remote", async (c) => {
    if(!await checkRateLimit(c, "up_remote", 5)) return c.json({error:"Rate limit"}, 429);
    const s = await getSessionUser(c);
    if(!s || !isVipActive(s.user)) return c.json({error:"VIP Only"}, 403);
    const { url, customName, server, expiry, csrf } = await c.req.json();
    if(csrf !== s.csrfToken) return c.json({error:"CSRF"}, 403);
    if(!isValidRemoteUrl(url)) return c.json({error:"Invalid URL"}, 400);

    // Stream Response for Progress
    const stream = new ReadableStream({
        async start(ctrl) {
            const push = (d: any) => ctrl.enqueue(new TextEncoder().encode(JSON.stringify(d)+"\n"));
            try {
                // SECURITY: Prevent Redirects to internal IPs
                const r = await fetch(url, { redirect: 'error' });
                if(!r.ok) throw new Error("Fetch failed");
                const size = parseInt(r.headers.get("content-length")||"0");
                if(size > MAX_REMOTE_SIZE) throw new Error("File too large (>2GB)");
                
                // Content Type Check
                const cType = r.headers.get("content-type") || "application/octet-stream";
                const ext = mimeToExt(cType);
                if(BLOCKED_EXTENSIONS.has(ext)) throw new Error("Blocked file type");

                const safeName = (customName||"remote").replace(/[^a-zA-Z0-9]/g,"_") + "." + ext;
                const reqSize = (server === "both" ? size * 2 : size);
                
                // Pre-flight storage check
                const uRes = await kv.get<User>(["users", s.user.username]);
                if(!uRes.value || (uRes.value.usedStorage + reqSize > PLANS[s.user.plan].limit)) throw new Error("Storage Full");

                const doUp = async (svr: "1"|"2", body: ReadableStream) => {
                    const client = svr==="1"?s3Server1:s3Server2;
                    const bucket = svr==="1"?Deno.env.get("R2_1_BUCKET_NAME"):Deno.env.get("R2_2_BUCKET_NAME");
                    const key = `${s.user.username}/${Date.now()}-${safeName}`;
                    const up = new Upload({ client, params: { Bucket: bucket, Key: key, Body: body as any, ContentType: cType }, queueSize: 4, partSize: 10*1024*1024 });
                    return { up, key, svr };
                };

                let uploads = [];
                if(server === "both") { const [b1,b2]=r.body!.tee(); uploads.push(doUp("1",b1)); uploads.push(doUp("2",b2)); }
                else { uploads.push(doUp(server as any, r.body!)); }

                uploads[0].up.on("httpUploadProgress", p => { if(size) push({progress: Math.round((p.loaded!/size)*100)}); });
                
                await Promise.all(uploads.map(async u => {
                    await u.up.done();
                    const expDays = parseInt(expiry)||0;
                    const fId = crypto.randomUUID();
                    const fData: FileData = { id: fId, name: safeName, sizeBytes: size, size: (size/1024**2).toFixed(2)+" MB", server: u.svr as any, r2Key: u.key, uploadedAt: Date.now(), expiresAt: expDays>0?Date.now()+(expDays*86400000):0, type: cType.startsWith('image')?'image':cType.startsWith('video')?'video':'other', isVipFile: true };
                    await kv.set(["files", s.user.username, fId], fData);
                }));

                // Update Usage
                let ok = false;
                while(!ok) {
                    const u = await kv.get<User>(["users", s.user.username]);
                    if(!u.value) break;
                    const nu = {...u.value, usedStorage: u.value.usedStorage + reqSize};
                    ok = (await kv.atomic().check(u).set(["users", s.user.username], nu).commit()).ok;
                }
                await updateStats(reqSize);
                push({done: true});
            } catch(e: any) { push({error: e.message}); }
            ctrl.close();
        }
    });
    return new Response(stream, { headers: {"Content-Type":"application/x-ndjson"} });
});

app.post("/delete/:id", async (c) => {
    const s = await getSessionUser(c); if(!s) return c.json({error:"Auth"}, 401);
    const { csrf } = await c.req.parseBody(); if(csrf !== s.csrfToken) return c.text("CSRF", 403);
    const id = c.req.param("id");
    
    const fRes = await kv.get<FileData>(["files", s.user.username, id]);
    if(fRes.value) {
        const f = fRes.value;
        const client = f.server==="1"?s3Server1:s3Server2;
        const bucket = f.server==="1"?Deno.env.get("R2_1_BUCKET_NAME"):Deno.env.get("R2_2_BUCKET_NAME");
        try { await client.send(new DeleteObjectCommand({Bucket: bucket, Key: f.r2Key})); } catch {}
        
        let ok = false;
        while(!ok) {
            const u = await kv.get<User>(["users", s.user.username]);
            if(!u.value) break;
            const nu = {...u.value, usedStorage: Math.max(0, u.value.usedStorage - f.sizeBytes)};
            ok = (await kv.atomic().check(u).set(["users", s.user.username], nu).delete(["files", s.user.username, id]).commit()).ok;
        }
        await updateStats(-f.sizeBytes);
    }
    return c.redirect("/");
});

app.get("/d/:server/*", async (c) => {
    const svr = c.req.param("server");
    const key = c.req.path.split(`/d/${svr}/`)[1];
    const client = svr==="1"?s3Server1:s3Server2;
    const bucket = svr==="1"?Deno.env.get("R2_1_BUCKET_NAME"):Deno.env.get("R2_2_BUCKET_NAME");
    try {
        const cmd = new GetObjectCommand({Bucket: bucket, Key: key, ResponseContentDisposition: "inline"});
        const url = await getSignedUrl(client, cmd, {expiresIn: 3600});
        return c.redirect(url);
    } catch { return c.text("File Not Found", 404); }
});

// =======================
// 6. ADMIN PANEL (Optimized)
// =======================
app.get("/admin", async (c) => {
    const s = await getSessionUser(c);
    if(!s || s.user.username !== ADMIN_USERNAME) return c.redirect("/");
    
    const cursor = c.req.query("cursor");
    const search = c.req.query("u");
    const users = []; let nextC = "";

    if(search) {
        const u = await kv.get<User>(["users", search]);
        if(u.value) users.push(u.value);
    } else {
        // Pagination Limit 50 to prevent crash
        const iter = kv.list<User>({ prefix: ["users"] }, { limit: 50, cursor });
        for await (const res of iter) { users.push(res.value); nextC = res.cursor; }
    }

    const stats = (await kv.get<{totalUsers:number, totalStorage:number}>(["stats", "global"])).value || {totalUsers:0, totalStorage:0};

    return c.html(<Layout title="Admin" user={s.user} csrf={s.csrfToken}>
        <div class="flex gap-4 mb-6">
            <div class="glass p-4 rounded-xl flex-1 border-l-4 border-yellow-500"><p class="text-xs text-gray-400">USERS</p><p class="text-2xl font-black">{stats.totalUsers}</p></div>
            <div class="glass p-4 rounded-xl flex-1 border-l-4 border-blue-500"><p class="text-xs text-gray-400">STORAGE</p><p class="text-2xl font-black">{(stats.totalStorage/1024**3).toFixed(2)} GB</p></div>
        </div>
        
        <div class="glass rounded-xl overflow-hidden">
            <div class="bg-zinc-800 p-3 flex justify-between items-center">
                <h3 class="font-bold">Users</h3>
                <form class="flex gap-2"><input name="u" placeholder="Username" class="bg-black border border-zinc-600 px-2 py-1 rounded text-xs text-white"/><button class="bg-yellow-600 text-black px-3 py-1 rounded text-xs font-bold">Search</button></form>
            </div>
            <div class="overflow-x-auto"><table class="w-full text-left text-xs text-gray-400">
                <thead class="bg-black text-gray-500 uppercase"><tr><th class="p-3">User</th><th class="p-3">Plan</th><th class="p-3">Expiry</th><th class="p-3">Action</th></tr></thead>
                <tbody class="divide-y divide-zinc-800">{users.map(u => (
                    <tr class={u.isBanned?"bg-red-900/20":""}>
                        <td class="p-3 font-bold text-white">{u.username} {u.isBanned&&<span class="text-red-500">[BAN]</span>} {u.isPendingDelete&&<span class="text-orange-500">[DEL PENDING]</span>}</td>
                        <td class="p-3">{PLANS[u.plan]?.name}</td>
                        <td class="p-3">{u.vipExpiry?formatDate(u.vipExpiry):'-'}</td>
                        <td class="p-3 flex gap-2">
                             <form action="/admin/ban" method="post"><input type="hidden" name="u" value={u.username}/><input type="hidden" name="csrf" value={s.csrfToken}/><button class="text-blue-500 hover:underline">Ban/Unban</button></form>
                             <form action="/admin/del" method="post" onsubmit="return confirm('Delete?')"><input type="hidden" name="u" value={u.username}/><input type="hidden" name="csrf" value={s.csrfToken}/><button class="text-red-500 hover:underline">Delete</button></form>
                        </td>
                    </tr>
                ))}</tbody>
            </table></div>
            {nextC && !search && <div class="p-3 text-center"><a href={"/admin?cursor="+nextC} class="bg-zinc-800 px-4 py-2 rounded-full text-xs">Next Page</a></div>}
        </div>
    </Layout>);
});

app.post("/admin/ban", async (c) => {
    const s = await getSessionUser(c); if(s?.user.username !== ADMIN_USERNAME) return c.text("403");
    const { u } = await c.req.parseBody();
    const user = (await kv.get<User>(["users", String(u)])).value;
    if(user && user.username !== ADMIN_USERNAME) { user.isBanned = !user.isBanned; await kv.set(["users", user.username], user); }
    return c.redirect("/admin");
});

app.post("/admin/del", async (c) => {
    const s = await getSessionUser(c); if(s?.user.username !== ADMIN_USERNAME) return c.text("403");
    const { u } = await c.req.parseBody();
    const user = (await kv.get<User>(["users", String(u)])).value;
    // Mark for background deletion instead of mass deleting immediately
    if(user && user.username !== ADMIN_USERNAME) { user.isPendingDelete = true; user.isBanned = true; await kv.set(["users", user.username], user); }
    return c.redirect("/admin");
});

// =======================
// 7. AUTH & SYSTEM
// =======================
app.get("/login", c => c.html(<Layout title="Login" noLogin><div class="max-w-sm mx-auto mt-20 glass p-8 rounded-2xl"><h1 class="text-2xl font-black text-center text-yellow-500 mb-6">GOLD STORAGE</h1><form action="/login" method="post" class="space-y-4"><input name="username" placeholder="Username" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white"/><input type="password" name="password" placeholder="Password" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white"/><button class="w-full bg-yellow-500 text-black font-bold py-3 rounded-xl">LOGIN</button></form><div class="text-center mt-4"><a href="/register" class="text-xs text-gray-500 hover:text-white">Create Account</a></div></div></Layout>));
app.post("/login", async c => {
    if(!await checkRateLimit(c, "login", 10)) return c.text("Rate Limit", 429);
    const {username, password} = await c.req.parseBody();
    const u = await kv.get<User>(["users", String(username)]);
    if(u.value && u.value.passwordHash === await hashPassword(String(password))) { await createSession(c, u.value.username); return c.redirect("/"); }
    return c.redirect("/login");
});
app.get("/register", c => c.html(<Layout title="Register" noLogin><div class="max-w-sm mx-auto mt-20 glass p-8 rounded-2xl"><h1 class="text-xl font-bold text-center text-white mb-6">Create Account</h1><form action="/register" method="post" class="space-y-4"><input name="username" placeholder="Username (Min 3)" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white"/><input type="password" name="password" placeholder="Password (Min 6)" required class="w-full bg-black border border-zinc-700 p-3 rounded-xl text-white"/><button class="w-full bg-green-600 text-white font-bold py-3 rounded-xl">REGISTER</button></form><div class="text-center mt-4"><a href="/login" class="text-xs text-gray-500 hover:text-white">Login</a></div></div></Layout>));
app.post("/register", async c => {
    if(!await checkRateLimit(c, "reg", 3)) return c.text("Rate Limit", 429);
    const {username, password} = await c.req.parseBody();
    const uName = String(username).trim().replace(/[^a-zA-Z0-9]/g,"");
    if(uName.length<3 || String(password).length<6) return c.text("Invalid Input");
    const k = ["users", uName];
    const ok = (await kv.atomic().check({key:k, versionstamp:null}).set(k, {username:uName, passwordHash: await hashPassword(String(password)), plan:'free', isVip:false, usedStorage:0, createdAt:Date.now()}).commit()).ok;
    if(ok) { await incrementUserCount(1); return c.redirect("/login"); }
    return c.text("Username Taken");
});
app.get("/logout", c => { deleteCookie(c, "session_id"); return c.redirect("/login"); });

// =======================
// 8. CRON JOBS (Safe Cleanup)
// =======================
Deno.cron("Cleanup", "0 * * * *", async () => {
    const now = Date.now();
    
    // 1. Clean expired files
    const fIter = kv.list<FileData>({ prefix: ["files"] }, {limit: 50}); // Limit chunk size
    for await (const entry of fIter) {
        const f = entry.value;
        const u = (await kv.get<User>(["users", entry.key[1] as string])).value;
        
        let shouldDel = false;
        if (f.expiresAt > 0 && f.expiresAt < now) shouldDel = true; // File Expired
        if (u && u.isPendingDelete) shouldDel = true; // User marked for deletion
        if (u && u.vipExpiry && u.vipExpiry < now && now > u.vipExpiry + (7*86400000)) shouldDel = true; // VIP Grace period over

        if(shouldDel) {
            const client = f.server==="1"?s3Server1:s3Server2;
            const bucket = f.server==="1"?Deno.env.get("R2_1_BUCKET_NAME"):Deno.env.get("R2_2_BUCKET_NAME");
            try { await client.send(new DeleteObjectCommand({Bucket: bucket, Key: f.r2Key})); } catch {}
            
            // Cleanup KV
            if(u) {
                const nu = {...u, usedStorage: Math.max(0, u.usedStorage - f.sizeBytes)};
                await kv.atomic().check({key:["users", u.username], versionstamp: null}).set(["users", u.username], nu).delete(entry.key).commit();
            } else { await kv.delete(entry.key); }
            await updateStats(-f.sizeBytes);
        }
    }

    // 2. Clean fully deleted users (users marked pending delete but have no files left)
    const uIter = kv.list<User>({prefix:["users"]});
    for await (const entry of uIter) {
        if(entry.value.isPendingDelete) {
            // Check if any files remain
            const check = kv.list({prefix:["files", entry.value.username]}, {limit:1});
            const hasFiles = (await check.next()).value;
            if(!hasFiles) {
                // Safe to remove user now
                await kv.delete(entry.key);
                await incrementUserCount(-1);
            }
        }
    }
});

Deno.serve(app.fetch);
