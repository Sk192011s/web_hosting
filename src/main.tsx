/** @jsxImportSource npm:hono@4/jsx */
import { Hono } from "npm:hono@4";
import { getCookie, setCookie, deleteCookie } from "npm:hono@4/cookie";
import { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand, HeadObjectCommand } from "npm:@aws-sdk/client-s3";
import { getSignedUrl } from "npm:@aws-sdk/s3-request-presigner";
import { Upload } from "npm:@aws-sdk/lib-storage"; 

const app = new Hono();
const kv = await Deno.openKv();

// =======================
// 1. CONFIG
// =======================
const ADMIN_USERNAME = "soekyawwin"; // <--- Change this
const SECRET_KEY = Deno.env.get("SECRET_SALT") || "change-this-secret-key-securely";

// Storage Quota
const FREE_STORAGE_LIMIT = 50 * 1024 * 1024 * 1024; // 50 GB
const VIP_STORAGE_LIMIT = 100 * 1024 * 1024 * 1024; // 100 GB
const MAX_REMOTE_SIZE = 1.5 * 1024 * 1024 * 1024;   // 1.5 GB

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
// 2. HELPERS
// =======================
interface User { username: string; passwordHash: string; isVip: boolean; vipExpiry?: number; usedStorage: number; createdAt: number; }
interface FileData { id: string; name: string; sizeBytes: number; size: string; server: "1" | "2"; r2Key: string; uploadedAt: number; expiresAt: number; type: "image" | "video" | "other"; isVipFile: boolean; }

async function hashPassword(password: string) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: enc.encode(SECRET_KEY), iterations: 100000, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const exported = await crypto.subtle.exportKey("raw", key);
    return Array.from(new Uint8Array(exported)).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function getUser(username: string) { const res = await kv.get<User>(["users", username]); return res.value; }
function checkVipStatus(user: User): boolean { return user.vipExpiry ? user.vipExpiry > Date.now() : user.isVip; }
function formatDate(ts: number) { return new Date(ts).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }); }
function mimeToExt(mime: string): string { const m: any = {'video/mp4':'mp4','video/webm':'webm','video/x-matroska':'mkv','image/jpeg':'jpg','image/png':'png'}; return m[mime.split(';')[0]] || 'bin'; }

// =======================
// 3. FRONTEND UI
// =======================
const mainScript = `
<script>
    // Global VIP Status passed from server
    const IS_USER_VIP = window.IS_VIP_USER || false;

    function switchTab(tab) {
        const url = new URL(window.location);
        url.searchParams.set('type', tab);
        url.searchParams.delete('cursor'); 
        window.location.href = url.toString();
    }
    
    function switchUploadMode(mode) {
        // VIP Check for Remote Mode
        if (mode === 'remote' && !IS_USER_VIP) {
            alert("🔒 VIP Feature Only! \\n\\nRemote Upload (URL Upload) ကိုအသုံးပြုရန် VIP အဆင့်မြှင့်တင်ပါ။");
            return;
        }

        document.getElementById('mode-local').classList.add('hidden');
        document.getElementById('mode-remote').classList.add('hidden');
        document.getElementById('btn-mode-local').classList.remove('bg-yellow-500', 'text-black');
        document.getElementById('btn-mode-remote').classList.remove('bg-yellow-500', 'text-black');
        
        document.getElementById('mode-' + mode).classList.remove('hidden');
        document.getElementById('btn-mode-' + mode).classList.add('bg-yellow-500', 'text-black');
    }

    // --- SEARCH FUNCTION ---
    function filterFiles() {
        const input = document.getElementById('searchInput');
        const filter = input.value.toLowerCase();
        const nodes = document.getElementsByClassName('file-item');

        for (let i = 0; i < nodes.length; i++) {
            let name = nodes[i].getAttribute('data-name').toLowerCase();
            if (name.includes(filter)) {
                nodes[i].style.display = ""; // Show
            } else {
                nodes[i].style.display = "none"; // Hide
            }
        }
    }

    // --- EDIT EXPIRY (VIP) ---
    function openEditModal(fileId, currentName, currentExpiry) {
        if (!IS_USER_VIP) { alert("VIP Only"); return; }
        const days = prompt("သက်တမ်းရက်သတ်မှတ်ရန် (0 = Lifetime):", "30");
        if (days !== null) {
            fetch('/api/file/edit', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ fileId: fileId, days: days })
            }).then(r => r.json()).then(d => {
                if(d.success) window.location.reload();
                else alert(d.error);
            });
        }
    }

    // --- LOCAL UPLOAD ---
    document.addEventListener("DOMContentLoaded", () => {
        const fileInput = document.getElementById('fileInput');
        const fileNameDisplay = document.getElementById('fileNameDisplay');
        if(fileInput) {
            fileInput.addEventListener('change', function() {
                if (this.files && this.files.length > 0) {
                    fileNameDisplay.innerText = this.files[0].name;
                    fileNameDisplay.classList.add('text-yellow-500', 'font-bold');
                }
            });
        }
    });

    async function uploadLocal(event) {
        event.preventDefault();
        const fileInput = document.getElementById('fileInput');
        const submitBtn = document.getElementById('submitBtn');
        const progressBar = document.getElementById('progressBar');
        const progressContainer = document.getElementById('progressContainer');
        const progressText = document.getElementById('progressText');
        const form = document.getElementById('uploadForm');

        if(fileInput.files.length === 0) { alert("ဖိုင်ရွေးပါ"); return; }
        const file = fileInput.files[0];

        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Checking...';
        progressContainer.classList.remove('hidden');

        try {
            const formData = new FormData(form);
            const presignRes = await fetch("/api/upload/presign", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: file.name, type: file.type, size: file.size, server: formData.get("server"), customName: formData.get("customName") })
            });

            if (!presignRes.ok) throw new Error(await presignRes.text());
            const { url, key, fileId } = await presignRes.json();

            submitBtn.innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Uploading...';
            const xhr = new XMLHttpRequest();
            xhr.open("PUT", url, true);
            xhr.setRequestHeader("Content-Type", file.type);
            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    progressBar.style.width = percent + "%";
                    progressText.innerText = percent + "%";
                }
            };
            xhr.onload = async () => {
                if (xhr.status === 200) {
                    submitBtn.innerHTML = 'Saving...';
                    await fetch("/api/upload/complete", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key, fileId, server: formData.get("server"), expiry: formData.get("expiry") }) });
                    progressBar.classList.add('bg-green-500');
                    submitBtn.innerHTML = 'Success!';
                    setTimeout(() => window.location.reload(), 1000);
                } else { throw new Error("Upload Failed"); }
            };
            xhr.send(file);
        } catch (error) { alert(error.message); submitBtn.disabled = false; submitBtn.innerText = "Try Again"; progressContainer.classList.add('hidden'); }
    }

    // --- REMOTE UPLOAD ---
    async function uploadRemote(event) {
        event.preventDefault();
        const urlInput = document.getElementById('remoteUrl');
        const nameInput = document.getElementById('remoteName');
        const serverInput = document.querySelector('input[name="server_remote"]:checked');
        const expiryInput = document.querySelector('select[name="expiry_remote"]');
        const submitBtn = document.getElementById('remoteBtn');
        const progressBar = document.getElementById('progressBarRemote');
        const progressContainer = document.getElementById('progressContainerRemote');
        const progressText = document.getElementById('progressTextRemote');

        if(!urlInput.value) { alert("URL ထည့်ပါ"); return; }
        
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-satellite-dish fa-spin"></i> Starting...';
        progressContainer.classList.remove('hidden');
        progressBar.style.width = "0%";

        try {
            const response = await fetch('/api/upload/remote', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlInput.value, customName: nameInput.value, server: serverInput.value, expiry: expiryInput.value })
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
                    if (!line) continue;
                    try {
                        const msg = JSON.parse(line);
                        if (msg.error) throw new Error(msg.error);
                        if (msg.progress) {
                            // Update Status based on progress
                            if (msg.progress < 99) {
                                submitBtn.innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Downloading...';
                            } else {
                                submitBtn.innerHTML = '<i class="fa-solid fa-floppy-disk fa-spin"></i> Saving to Cloud...';
                            }
                            progressBar.style.width = msg.progress + "%";
                            progressText.innerText = msg.progress + "%";
                        }
                        if (msg.done) {
                            progressBar.classList.add('bg-green-500');
                            submitBtn.innerHTML = 'Success!';
                            setTimeout(() => window.location.reload(), 1000);
                        }
                    } catch (e) { throw e; }
                }
            }
        } catch (e) {
            alert("Error: " + e.message);
            submitBtn.disabled = false;
            submitBtn.innerText = "Try Again";
            progressContainer.classList.add('hidden');
        }
    }
</script>
`;

const Layout = (props: { children: any; title?: string; user?: User | null }) => {
    const isVip = props.user ? checkVipStatus(props.user) : false;
    return (
    <html>
        <head>
            <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>{props.title || "Gold Storage Pro"}</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" />
            <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap" rel="stylesheet" />
            <style>{`body { font-family: 'Padauk', sans-serif; background-color: #09090b; color: #e4e4e7; } .glass { background: rgba(39, 39, 42, 0.6); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.05); } .custom-scroll::-webkit-scrollbar { width: 6px; } .custom-scroll::-webkit-scrollbar-track { background: #18181b; } .custom-scroll::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 3px; }`}</style>
            <script dangerouslySetInnerHTML={{__html: `window.IS_VIP_USER = ${isVip};`}} />
        </head>
        <body data-vip={isVip ? "true" : "false"}>
            <nav class="fixed top-0 w-full z-50 glass border-b border-zinc-800"><div class="max-w-5xl mx-auto px-4 py-3 flex justify-between items-center"><a href="/" class="text-xl font-black text-transparent bg-clip-text bg-gradient-to-r from-yellow-400 to-yellow-600 italic tracking-tighter"><i class="fa-solid fa-cube text-yellow-500 mr-2"></i>GOLD STORAGE</a>{props.user ? (<div class="flex gap-3 items-center"><div class="hidden sm:flex flex-col items-end leading-tight"><span class="text-xs font-bold text-gray-300">{props.user.username}</span>{checkVipStatus(props.user) ? <span class="text-[9px] text-yellow-500 font-bold">VIP</span> : <span class="text-[9px] text-gray-500 font-bold">FREE</span>}</div>{props.user.username === ADMIN_USERNAME && <a href="/admin" class="w-8 h-8 flex items-center justify-center bg-purple-600 rounded-full hover:bg-purple-500 text-white"><i class="fa-solid fa-shield-halved text-xs"></i></a>}<a href="/logout" class="w-8 h-8 flex items-center justify-center bg-zinc-800 border border-zinc-700 rounded-full hover:bg-red-600/20 hover:text-red-500"><i class="fa-solid fa-power-off text-xs"></i></a></div>) : (<a href="/login" class="text-xs bg-yellow-500 text-black px-4 py-2 rounded-full font-bold hover:bg-yellow-400 transition">ဝင်မည်</a>)}</div></nav>
            <main class="pt-20 pb-10 px-4 max-w-5xl mx-auto">{props.children}</main>
            <div dangerouslySetInnerHTML={{__html: mainScript}} />
        </body>
    </html>
)};

// =======================
// 4. MAIN ROUTES
// =======================
app.get("/", async (c) => {
    const cookie = getCookie(c, "auth");
    if(!cookie) return c.redirect("/login");
    const user = await getUser(cookie);
    if(!user) return c.redirect("/login");

    const isVip = checkVipStatus(user);
    const filterType = c.req.query('type') || 'all';
    const cursor = c.req.query('cursor');

    const iter = kv.list<FileData>({ prefix: ["files", user.username] }, { reverse: true, limit: 30, cursor: cursor });
    const files = []; let nextCursor = "";
    for await (const res of iter) { if (filterType === 'all' || res.value.type === filterType) { files.push(res.value); } nextCursor = res.cursor; }

    const totalGB = (user.usedStorage / 1024 / 1024 / 1024).toFixed(2);
    const displayLimit = isVip ? "100 GB" : "50 GB";
    const limitBytes = isVip ? VIP_STORAGE_LIMIT : FREE_STORAGE_LIMIT; 
    const usedPercent = Math.min(100, (user.usedStorage / limitBytes) * 100);

    return c.html(<Layout user={user}>
        {/* Stats */}
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <div class="glass p-5 rounded-2xl relative overflow-hidden group"><p class="text-xs text-zinc-400 uppercase font-bold mb-1">အကောင့်</p><p class={`text-2xl font-black ${isVip ? 'text-yellow-500' : 'text-zinc-300'}`}>{isVip ? "VIP PRO" : "Free Plan"}</p>{isVip && user.vipExpiry && <p class="text-[10px] text-green-400 mt-2 font-mono bg-green-900/20 inline-block px-2 py-1 rounded">EXP: {formatDate(user.vipExpiry)}</p>}<a href="/change-password" class="absolute bottom-4 right-4 text-xs text-zinc-500 hover:text-white transition"><i class="fa-solid fa-key mr-1"></i> Pass</a></div>
            <div class="glass p-5 rounded-2xl relative"><div class="flex justify-between items-end mb-2"><div><p class="text-xs text-zinc-400 uppercase font-bold">Storage</p><p class="text-xl font-bold text-white">{totalGB} <span class="text-sm text-zinc-500">GB / {displayLimit}</span></p></div><span class="text-2xl font-black text-zinc-600">{usedPercent.toFixed(0)}%</span></div><div class="w-full bg-zinc-800 rounded-full h-3 overflow-hidden"><div class={`h-full rounded-full ${isVip ? 'bg-gradient-to-r from-yellow-600 to-yellow-400' : 'bg-zinc-500'}`} style={`width: ${usedPercent}%`}></div></div></div>
            <div class="glass p-5 rounded-2xl flex items-center justify-between"><div><p class="text-xs text-zinc-400 uppercase font-bold">Status</p><p class="text-sm font-bold text-green-500">Active</p></div><div class="w-12 h-12 rounded-xl bg-blue-500/10 flex items-center justify-center text-blue-500 text-2xl"><i class="fa-solid fa-signal"></i></div></div>
        </div>
        
        {/* Upload Tabs */}
        <div class="glass p-6 rounded-2xl mb-8 border border-zinc-700/50 shadow-2xl">
            <div class="flex gap-4 mb-6 border-b border-zinc-700 pb-2">
                <button id="btn-mode-local" onclick="switchUploadMode('local')" class="px-4 py-2 text-xs font-bold rounded-lg bg-yellow-500 text-black transition">Direct Upload</button>
                {/* Free users also see this button now */}
                <button id="btn-mode-remote" onclick="switchUploadMode('remote')" class="px-4 py-2 text-xs font-bold rounded-lg bg-zinc-800 text-gray-400 hover:text-white transition"><i class="fa-solid fa-globe mr-1"></i> Remote URL {isVip ? "" : "(VIP)"}</button>
            </div>

            {/* LOCAL UPLOAD */}
            <form id="uploadForm" onsubmit="uploadLocal(event)" class="space-y-5" id="mode-local">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                    <div><label class="text-xs font-bold text-zinc-400 uppercase mb-2 block">ဖိုင်နာမည် (Optional)</label><input name="customName" placeholder="File Name..." class="w-full bg-zinc-900 border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none transition" /></div>
                    <div>
                        <label class="text-xs font-bold text-zinc-400 uppercase mb-2 block">သက်တမ်း</label>
                        {isVip ? (<select name="expiry" class="w-full bg-zinc-900 border border-yellow-600/50 rounded-xl p-3 text-sm text-yellow-500 font-bold outline-none"><option value="0">Lifetime</option><option value="7">1 Week</option><option value="30">1 Month</option></select>) : (<div class="relative"><input disabled value="30 Days (Free Limit)" class="w-full bg-zinc-900 border border-red-900/30 text-red-400 rounded-xl p-3 text-sm font-bold cursor-not-allowed" /><input type="hidden" name="expiry" value="30" /></div>)}
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <label class="cursor-pointer relative"><input type="radio" name="server" value="1" class="peer sr-only" checked /><div class="p-3 bg-zinc-900 border border-zinc-700 rounded-xl peer-checked:border-blue-500 peer-checked:bg-blue-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-sm block text-gray-300 peer-checked:text-white">Server 1</span></div></label>
                    <label class="cursor-pointer relative"><input type="radio" name="server" value="2" class="peer sr-only" /><div class="p-3 bg-zinc-900 border border-zinc-700 rounded-xl peer-checked:border-yellow-500 peer-checked:bg-yellow-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-sm block text-gray-300 peer-checked:text-white">Server 2</span></div></label>
                </div>
                <div class="border-2 border-dashed border-zinc-700 rounded-2xl p-8 text-center hover:border-yellow-500/50 hover:bg-zinc-800/50 transition cursor-pointer group relative">
                    <input type="file" id="fileInput" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"/>
                    <div class="space-y-2 pointer-events-none"><div class="w-12 h-12 bg-zinc-800 rounded-full flex items-center justify-center mx-auto text-zinc-400 group-hover:text-yellow-500 transition"><i id="uploadIcon" class="fa-solid fa-plus text-xl"></i></div><p id="fileNameDisplay" class="text-sm font-bold text-zinc-300 truncate px-4">Choose File</p><p class="text-[10px] text-zinc-500">{isVip ? "Unlimited" : "Limit: 50GB"}</p></div>
                </div>
                <div id="progressContainer" class="hidden"><div class="flex justify-between text-[10px] uppercase font-bold text-zinc-400 mb-1"><span>Uploading...</span><span id="progressText">0%</span></div><div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden"><div id="progressBar" class="bg-yellow-500 h-full rounded-full transition-all duration-300" style="width: 0%"></div></div></div>
                <button id="submitBtn" class="w-full bg-gradient-to-r from-yellow-600 to-yellow-500 text-black font-bold py-3.5 rounded-xl shadow-lg hover:brightness-110 transition active:scale-95">တင်မည်</button>
            </form>

            {/* REMOTE UPLOAD FORM (VIP Logic Handled in JS) */}
            <form id="mode-remote" onsubmit="uploadRemote(event)" class="space-y-5 hidden">
                <div><label class="text-xs font-bold text-zinc-400 uppercase mb-2 block">Direct Video/File URL</label><input id="remoteUrl" type="url" placeholder="https://example.com/video.mp4" class="w-full bg-zinc-900 border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none transition" /></div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                    <div><label class="text-xs font-bold text-zinc-400 uppercase mb-2 block">File Name</label><input id="remoteName" placeholder="myvideo.mp4" class="w-full bg-zinc-900 border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none transition" /></div>
                    <div><label class="text-xs font-bold text-zinc-400 uppercase mb-2 block">Expiry</label><select name="expiry_remote" class="w-full bg-zinc-900 border border-yellow-600/50 rounded-xl p-3 text-sm text-yellow-500 font-bold outline-none"><option value="0">Lifetime</option><option value="7">1 Week</option><option value="30">1 Month</option></select></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <label class="cursor-pointer relative"><input type="radio" name="server_remote" value="1" class="peer sr-only" checked /><div class="p-3 bg-zinc-900 border border-zinc-700 rounded-xl peer-checked:border-blue-500 peer-checked:bg-blue-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-sm block text-gray-300 peer-checked:text-white">Server 1</span></div></label>
                    <label class="cursor-pointer relative"><input type="radio" name="server_remote" value="2" class="peer sr-only" /><div class="p-3 bg-zinc-900 border border-zinc-700 rounded-xl peer-checked:border-yellow-500 peer-checked:bg-yellow-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-sm block text-gray-300 peer-checked:text-white">Server 2</span></div></label>
                </div>
                <div id="progressContainerRemote" class="hidden"><div class="flex justify-between text-[10px] uppercase font-bold text-zinc-400 mb-1"><span>Processing...</span><span id="progressTextRemote">0%</span></div><div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden"><div id="progressBarRemote" class="bg-yellow-500 h-full rounded-full transition-all duration-300" style="width: 0%"></div></div></div>
                <button id="remoteBtn" class="w-full bg-zinc-800 text-white border border-zinc-700 font-bold py-3.5 rounded-xl shadow-lg hover:bg-yellow-600 hover:text-black transition">Remote Upload (Max 1.5GB)</button>
            </form>
        </div>

        {/* File List & Search */}
        <div class="flex flex-col md:flex-row md:items-center justify-between mb-4 gap-4">
            <h3 class="font-bold text-white text-sm uppercase tracking-wide"><i class="fa-solid fa-list-ul mr-2 text-zinc-500"></i> My Files</h3>
            <div class="flex gap-2 w-full md:w-auto">
                <input id="searchInput" onkeyup="filterFiles()" placeholder="Search files..." class="bg-zinc-900 border border-zinc-700 text-white text-xs p-2 rounded-lg outline-none focus:border-yellow-500 w-full md:w-48" />
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
                    const downloadLink = `/d/${f.server}/${f.r2Key}`;
                    const viewLink = `/d/${f.server}/${f.r2Key}?action=view`;
                    return (
                    <div class="file-item bg-zinc-800/50 hover:bg-zinc-800 p-3 rounded-xl border border-transparent hover:border-zinc-600 group transition" data-name={f.name}>
                        {/* Mobile Layout Fix: Column on small, Row on md */}
                        <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
                            
                            {/* Icon + Info */}
                            <div class="flex items-start gap-3 overflow-hidden w-full">
                                <div class={`w-10 h-10 rounded-lg flex items-center justify-center text-lg flex-shrink-0 mt-1 ${f.type === 'image' ? 'bg-yellow-500/10 text-yellow-500' : f.type === 'video' ? 'bg-blue-500/10 text-blue-500' : 'bg-zinc-700 text-zinc-400'}`}>
                                    <i class={`fa-solid ${f.type === 'image' ? 'fa-image' : f.type === 'video' ? 'fa-clapperboard' : 'fa-file'}`}></i>
                                </div>
                                <div class="min-w-0 w-full">
                                    <a href={viewLink} target="_blank" class="font-bold text-sm text-zinc-200 group-hover:text-yellow-500 transition hover:underline block truncate">{f.name}</a>
                                    <div class="flex flex-wrap items-center gap-2 text-[10px] text-zinc-500 font-mono mt-1">
                                        <span class="bg-zinc-900 px-1.5 py-0.5 rounded text-zinc-400">{f.size}</span>
                                        <span>{formatDate(f.uploadedAt)}</span>
                                        {f.expiresAt > 0 ? (<span class="text-red-400 bg-red-900/10 px-1.5 py-0.5 rounded">Exp: {formatDate(f.expiresAt)}</span>) : (<span class="text-green-500 bg-green-900/10 px-1.5 py-0.5 rounded">Lifetime</span>)}
                                    </div>
                                </div>
                            </div>

                            {/* Action Buttons (Full width on mobile, auto on desktop) */}
                            <div class="flex gap-2 w-full md:w-auto justify-end border-t border-zinc-700/50 pt-2 md:pt-0 md:border-0">
                                {/* Edit Expiry (VIP Only) */}
                                {isVip && <button onclick={`openEditModal('${f.id}', '${f.name}', '${f.expiresAt}')`} class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-yellow-600 hover:text-black text-white rounded-lg transition" title="Edit Expiry"><i class="fa-solid fa-pen text-xs"></i></button>}
                                
                                <button onclick={`navigator.clipboard.writeText(window.location.origin + '${viewLink}'); this.innerHTML='<i class="fa-solid fa-check text-green-500"></i>'; setTimeout(()=>this.innerHTML='<i class="fa-regular fa-copy"></i>', 1000)`} class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-white hover:text-black text-white rounded-lg transition" title="Copy Stream Link"><i class="fa-regular fa-copy text-xs"></i></button>
                                
                                {(f.type === 'video' || f.type === 'image') && (<a href={viewLink} target="_blank" title="Play/View" class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-blue-500 text-white rounded-lg transition"><i class={`fa-solid ${f.type === 'video' ? 'fa-play' : 'fa-eye'} text-xs`}></i></a>)}
                                
                                <a href={downloadLink} target="_blank" title="Download" class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-green-600 text-white rounded-lg transition"><i class="fa-solid fa-download text-xs"></i></a>
                                
                                <form action={`/delete/${f.id}`} method="post" onsubmit="return confirm('ဖျက်မှာသေချာလား?')"><button class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-red-600 text-white rounded-lg transition"><i class="fa-solid fa-trash text-xs"></i></button></form>
                            </div>
                        </div>
                    </div>
                )})}
                {files.length === 0 && <div class="text-center text-zinc-500 py-12"><p>ဖိုင်များ မရှိသေးပါ</p></div>}
                {nextCursor && <div class="text-center pt-2"><a href={`/?type=${filterType}&cursor=${nextCursor}`} class="text-xs bg-zinc-800 text-zinc-400 px-4 py-2 rounded-full hover:bg-yellow-500 hover:text-black transition">Load More...</a></div>}
            </div>
        </div>
    </Layout>);
});

// =======================
// 5. API ROUTES
// =======================

// Presign
app.post("/api/upload/presign", async (c) => {
    const cookie = getCookie(c, "auth"); const user = await getUser(cookie || "");
    if(!user) return c.json({error: "Login required"}, 401);
    const { name, size, server, type, customName } = await c.req.json();
    const isVip = checkVipStatus(user);
    const limitBytes = isVip ? VIP_STORAGE_LIMIT : FREE_STORAGE_LIMIT;
    if (user.usedStorage + size > limitBytes) return c.json({ error: "Storage Limit Exceeded!" }, 400);

    let finalName = name;
    if (customName) { const ext = name.split('.').pop(); finalName = customName.endsWith('.' + ext) ? customName : customName + '.' + ext; }
    const safeName = finalName.replace(/[^a-zA-Z0-9.-]/g, "_");
    const r2Key = `${user.username}/${crypto.randomUUID()}-${safeName}`;
    const fileId = crypto.randomUUID();
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    const command = new PutObjectCommand({ Bucket: bucket, Key: r2Key, ContentType: type });
    const url = await getSignedUrl(client, command, { expiresIn: 900 });
    return c.json({ url, key: r2Key, fileId });
});

// Remote Upload
app.post("/api/upload/remote", async (c) => {
    const cookie = getCookie(c, "auth"); const user = await getUser(cookie || "");
    if(!user) return c.json({error: "Login required"}, 401);
    if(!checkVipStatus(user)) return c.json({error: "VIP Only Feature"}, 403);

    const bodyStream = new ReadableStream({
        async start(controller) {
            const enc = new TextEncoder();
            const push = (d: any) => controller.enqueue(enc.encode(JSON.stringify(d) + "\n"));
            try {
                const { url, customName, server, expiry } = await c.req.json();
                const r = await fetch(url);
                if(!r.ok) throw new Error("URL fetch failed");
                const totalSize = parseInt(r.headers.get("content-length") || "0");
                if(totalSize > MAX_REMOTE_SIZE) throw new Error("File too large (Max 1.5GB)");
                if(user.usedStorage + totalSize > VIP_STORAGE_LIMIT) throw new Error("Storage Full");

                const ext = mimeToExt(r.headers.get("content-type") || "") || "bin";
                const safeName = (customName || "remote_file").replace(/[^a-zA-Z0-9.-]/g, "_");
                const fileName = safeName.endsWith('.'+ext) ? safeName : safeName + '.' + ext;
                const r2Key = `${user.username}/${crypto.randomUUID()}-${fileName}`;
                const fileId = crypto.randomUUID();
                const client = server === "1" ? s3Server1 : s3Server2;
                const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");

                const upload = new Upload({
                    client: client,
                    params: { Bucket: bucket, Key: r2Key, Body: r.body as any, ContentType: r.headers.get("content-type") || "application/octet-stream" },
                    queueSize: 4, partSize: 20 * 1024 * 1024
                });
                upload.on("httpUploadProgress", p => { if(totalSize) push({progress: Math.round((p.loaded! / totalSize) * 100)}); });
                await upload.done();

                const expiryDays = parseInt(expiry) || 0;
                const type = r.headers.get("content-type")?.startsWith("image/") ? "image" : r.headers.get("content-type")?.startsWith("video/") ? "video" : "other";
                const fileData: FileData = { id: fileId, name: fileName, sizeBytes: totalSize, size: (totalSize / 1024 / 1024).toFixed(2) + " MB", server: server, r2Key: r2Key, uploadedAt: Date.now(), expiresAt: expiryDays > 0 ? Date.now() + (expiryDays * 86400000) : 0, type: type, isVipFile: true };
                await kv.atomic().set(["files", user.username, fileId], fileData).set(["users", user.username], { ...user, usedStorage: user.usedStorage + totalSize }).commit();
                push({done: true});
            } catch (e: any) { push({error: e.message}); }
            controller.close();
        }
    });
    return new Response(bodyStream, { headers: { "Content-Type": "application/x-ndjson" } });
});

// Edit File Expiry (VIP)
app.post("/api/file/edit", async (c) => {
    const cookie = getCookie(c, "auth"); const user = await getUser(cookie || "");
    if(!user || !checkVipStatus(user)) return c.json({error: "Unauthorized or not VIP"}, 403);
    const { fileId, days } = await c.req.json();
    const fileRes = await kv.get<FileData>(["files", user.username, fileId]);
    if(!fileRes.value) return c.json({error: "File not found"}, 404);
    
    const file = fileRes.value;
    const addDays = parseInt(days);
    file.expiresAt = addDays === 0 ? 0 : Date.now() + (addDays * 86400000);
    await kv.set(["files", user.username, fileId], file);
    return c.json({success: true});
});

// Upload Complete
app.post("/api/upload/complete", async (c) => {
    const cookie = getCookie(c, "auth"); const user = await getUser(cookie || "");
    if(!user) return c.json({error: "Unauthorized"}, 401);
    const { key, fileId, server, expiry } = await c.req.json();
    const isVip = checkVipStatus(user);
    const expiryDays = isVip ? (parseInt(expiry) || 0) : 30;
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    try {
        const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
        const sizeBytes = head.ContentLength || 0;
        const fileName = key.split("-").slice(1).join("-");
        const type = head.ContentType?.startsWith("image/") ? "image" : head.ContentType?.startsWith("video/") ? "video" : "other";
        const fileData: FileData = { id: fileId, name: fileName, sizeBytes: sizeBytes, size: (sizeBytes / 1024 / 1024).toFixed(2) + " MB", server: server, r2Key: key, uploadedAt: Date.now(), expiresAt: expiryDays > 0 ? Date.now() + (expiryDays * 86400000) : 0, type: type, isVipFile: isVip };
        await kv.atomic().set(["files", user.username, fileId], fileData).set(["users", user.username], { ...user, usedStorage: user.usedStorage + sizeBytes }).commit();
        return c.json({ success: true });
    } catch(e) { return c.json({ error: "Verification Failed" }, 500); }
});

// Download/Stream
app.get("/d/:server/*", async (c) => {
    const server = c.req.param("server");
    const rawKey = c.req.path.split(`/d/${server}/`)[1]; 
    if (!rawKey) return c.text("Invalid Key", 400);
    const action = c.req.query("action");
    const disposition = action === "view" ? "inline" : "attachment";
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    try {
        const command = new GetObjectCommand({ Bucket: bucket, Key: rawKey, ResponseContentDisposition: disposition });
        const url = await getSignedUrl(client, command, { expiresIn: 3600 });
        return c.redirect(url);
    } catch (e) { return c.text("File Not Found", 404); }
});

// =======================
// 6. ADMIN & AUTH (Same as before)
// =======================
app.get("/admin", async (c) => { 
    const cookie = getCookie(c, "auth"); const currentUser = await getUser(cookie || "");
    if(!currentUser || currentUser.username !== ADMIN_USERNAME) return c.redirect("/"); 
    const iter = kv.list<User>({ prefix: ["users"] }); 
    const users = []; let totalStorage = 0;
    for await (const res of iter) { users.push(res.value); totalStorage += res.value.usedStorage; }
    const totalGB = (totalStorage / 1024 / 1024 / 1024).toFixed(2);
    return c.html(<Layout title="Admin Panel" user={currentUser}><div class="space-y-6"><div class="grid grid-cols-2 gap-3"><div class="glass p-4 rounded-xl border-l-4 border-yellow-500 relative"><p class="text-[10px] text-gray-400 uppercase font-bold tracking-wider">Total Users</p><p class="text-2xl font-black mt-1">{users.length}</p></div><div class="glass p-4 rounded-xl border-l-4 border-blue-500 relative"><p class="text-[10px] text-gray-400 uppercase font-bold tracking-wider">Storage Used</p><p class="text-2xl font-black mt-1">{totalGB} <span class="text-sm font-normal text-gray-500">GB</span></p></div></div><div class="glass rounded-xl overflow-hidden border border-zinc-700/50"><div class="bg-zinc-800/50 px-4 py-3 border-b border-zinc-700 flex items-center justify-between"><h3 class="font-bold text-white text-sm">User Manager</h3><span class="text-[10px] text-gray-500 bg-zinc-900 px-2 py-1 rounded">Scroll >></span></div><div class="overflow-x-auto w-full"><table class="w-full text-left text-sm text-gray-400 min-w-[600px]"> <thead class="bg-zinc-900 text-[10px] uppercase font-bold text-gray-300 tracking-wider"><tr><th class="px-4 py-3">User</th><th class="px-4 py-3">Storage</th><th class="px-4 py-3">Status</th><th class="px-4 py-3 text-center">Actions</th></tr></thead><tbody class="divide-y divide-zinc-700/50">{users.map(u => (<tr class="hover:bg-zinc-800/40 transition"><td class="px-4 py-3 font-bold text-white">{u.username}</td><td class="px-4 py-3 text-xs font-mono">{(u.usedStorage/1024/1024).toFixed(2)} MB</td><td class="px-4 py-3">{checkVipStatus(u) ? <span class="bg-yellow-500/10 text-yellow-500 px-2 py-0.5 rounded text-[10px] font-bold">VIP</span> : <span class="bg-zinc-700/50 px-2 py-0.5 rounded text-[10px]">Free</span>}</td><td class="px-4 py-3 flex items-center justify-center gap-2"><a href={`/admin/files/${u.username}`} class="w-6 h-6 flex items-center justify-center bg-zinc-700 hover:bg-white hover:text-black rounded transition"><i class="fa-solid fa-folder-open text-[10px]"></i></a><form action="/admin/vip" method="post"><input type="hidden" name="username" value={u.username} /><select name="days" onchange="this.form.submit()" class="bg-black/40 border border-zinc-600 rounded text-[10px] py-1 px-2 outline-none w-20"><option value="">VIP...</option><option value="30">1 Mo</option><option value="150">5 Mo</option><option value="365">1 Yr</option><option value="-1">Rm</option></select></form>{u.username !== ADMIN_USERNAME && <div class="flex gap-1"><form action="/admin/delete-user" method="post" onsubmit="return confirm('Delete user & files?')"><input type="hidden" name="username" value={u.username} /><button class="w-6 h-6 flex items-center justify-center bg-red-500/10 text-red-500 hover:bg-red-500 hover:text-white rounded"><i class="fa-solid fa-trash text-[10px]"></i></button></form><form action="/admin/reset-pass" method="post" onsubmit="return confirm('Reset pass to 123456?')"><input type="hidden" name="username" value={u.username} /><button class="w-6 h-6 flex items-center justify-center bg-blue-500/10 text-blue-500 hover:bg-blue-500 hover:text-white rounded"><i class="fa-solid fa-key text-[10px]"></i></button></form></div>}</td></tr>))}</tbody></table></div></div></div></Layout>); 
});
app.get("/admin/files/:username", async (c) => { const cookie = getCookie(c, "auth"); const admin = await getUser(cookie || ""); if(admin?.username !== ADMIN_USERNAME) return c.redirect("/"); const targetUser = c.req.param("username"); const iter = kv.list<FileData>({ prefix: ["files", targetUser] }, { reverse: true, limit: 100 }); const files = []; for await (const res of iter) files.push(res.value); return c.html(<Layout title={`Files: ${targetUser}`} user={admin}><div class="flex items-center justify-between mb-6"><h2 class="text-xl font-bold text-white"><span class="text-yellow-500">{targetUser}</span>'s Files</h2><a href="/admin" class="bg-zinc-800 px-4 py-2 rounded-lg text-sm hover:bg-zinc-700">Back</a></div><div class="grid grid-cols-2 md:grid-cols-4 gap-4">{files.map(f => (<div class="glass p-3 rounded-xl group relative"><div class="h-24 bg-zinc-900/50 rounded-lg flex items-center justify-center mb-2 overflow-hidden relative">{f.type === 'image' ? (<img src={`/d/${f.server}/${f.r2Key}?action=view`} class="w-full h-full object-cover opacity-70 group-hover:opacity-100 transition" />) : (<i class={`fa-solid ${f.type === 'video' ? 'fa-clapperboard text-blue-500' : 'fa-file text-zinc-600'} text-3xl`}></i>)}</div><p class="text-xs font-bold text-white truncate">{f.name}</p><p class="text-[10px] text-zinc-500">{f.size} • {f.expiresAt ? formatDate(f.expiresAt) : "Lifetime"}</p><div class="absolute inset-0 bg-black/80 flex items-center justify-center gap-2 opacity-0 group-hover:opacity-100 transition rounded-xl"><a href={`/d/${f.server}/${f.r2Key}?action=view`} target="_blank" class="w-8 h-8 flex items-center justify-center bg-blue-600 text-white rounded-full"><i class="fa-solid fa-eye text-xs"></i></a><form action={`/delete/${f.id}`} method="post" onsubmit="return confirm('Delete file?')"><button class="w-8 h-8 flex items-center justify-center bg-red-600 text-white rounded-full"><i class="fa-solid fa-trash text-xs"></i></button></form></div></div>))}</div></Layout>); });
app.post("/admin/vip", async (c) => { const cookie = getCookie(c, "auth"); const admin = await getUser(cookie || ""); if(admin?.username !== ADMIN_USERNAME) return c.text("403"); const { username, days } = await c.req.parseBody(); const user = await getUser(String(username)); if(user && days) { const addDays = parseInt(String(days)); if (addDays === -1) { user.isVip = false; user.vipExpiry = undefined; } else { user.isVip = true; user.vipExpiry = (user.vipExpiry && user.vipExpiry > Date.now() ? user.vipExpiry : Date.now()) + (addDays * 86400000); } await kv.set(["users", user.username], user); } return c.redirect("/admin"); });
app.post("/admin/delete-user", async (c) => { const cookie = getCookie(c, "auth"); const admin = await getUser(cookie || ""); if(admin?.username !== ADMIN_USERNAME) return c.text("403"); const { username } = await c.req.parseBody(); const targetUser = String(username); const iter = kv.list<FileData>({ prefix: ["files", targetUser] }); for await (const res of iter) { await deleteFileFromR2(res.value); await kv.delete(res.key); } await kv.delete(["users", targetUser]); return c.redirect("/admin"); });
app.post("/admin/reset-pass", async (c) => { const cookie = getCookie(c, "auth"); const admin = await getUser(cookie || ""); if(admin?.username !== ADMIN_USERNAME) return c.text("403"); const { username } = await c.req.parseBody(); const user = await getUser(String(username)); if(user) { user.passwordHash = await hashPassword("123456"); await kv.set(["users", user.username], user); } return c.redirect("/admin"); });
async function deleteFileFromR2(f: FileData) { const bucket = Deno.env.get(`R2_${f.server}_BUCKET_NAME`); const client = f.server === "1" ? s3Server1 : s3Server2; try { await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: f.r2Key })); } catch (e) {} }
app.post("/delete/:id", async (c) => { const cookie = getCookie(c, "auth"); const user = await getUser(cookie || ""); if(!user) return c.redirect("/login"); const id = c.req.param("id"); const fileRes = await kv.get<FileData>(["files", user.username, id]); if (fileRes.value) { await deleteFileFromR2(fileRes.value); await kv.atomic().delete(["files", user.username, id]).set(["users", user.username], { ...user, usedStorage: Math.max(0, user.usedStorage - fileRes.value.sizeBytes) }).commit(); } return c.redirect("/"); });

app.get("/login", (c) => c.html(<Layout title="Login"><div class="max-w-sm mx-auto mt-24 glass p-8 rounded-2xl border border-zinc-700"><h1 class="text-3xl font-black mb-2 text-center text-yellow-500 italic">GOLD STORAGE</h1><form action="/login" method="post" class="space-y-4"><input name="username" placeholder="Username" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white" /><input type="password" name="password" placeholder="Password" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white" /><button class="w-full bg-gradient-to-r from-yellow-600 to-yellow-500 text-black font-bold py-3 rounded-xl hover:brightness-110">ဝင်မည်</button></form><p class="text-center text-xs mt-6 text-zinc-500">အကောင့်မရှိဘူးလား? <a href="/register" class="text-yellow-500 font-bold hover:underline">အကောင့်သစ်ဖွင့်မယ်</a></p></div></Layout>));
app.post("/login", async (c) => { const { username, password } = await c.req.parseBody(); const u = String(username).trim(); const user = await getUser(u); if (user && user.passwordHash === await hashPassword(String(password).trim())) { setCookie(c, "auth", u, { path: "/", httpOnly: true, secure: true, sameSite: "Strict", maxAge: 86400 * 30 }); return c.redirect("/"); } return c.html(<Layout><p class="text-center text-red-500 mt-20">Login Failed.</p></Layout>); });
app.get("/register", (c) => c.html(<Layout title="Register"><div class="max-w-sm mx-auto mt-24 glass p-8 rounded-2xl border border-zinc-700"><h1 class="text-xl font-bold mb-6 text-center text-white">အကောင့်သစ်ဖွင့်မည်</h1><form action="/register" method="post" class="space-y-4"><input name="username" placeholder="Username" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white" /><input type="password" name="password" placeholder="Password" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white" /><button class="w-full bg-green-600 hover:bg-green-500 py-3 rounded-xl font-bold">စာရင်းသွင်းမည်</button></form></div></Layout>));
app.post("/register", async (c) => { const { username, password } = await c.req.parseBody(); const u = String(username).trim(); if (await getUser(u)) return c.html(<Layout><p class="text-center text-red-500 mt-20">Username Taken.</p></Layout>); const newUser: User = { username: u, passwordHash: await hashPassword(String(password)), isVip: false, usedStorage: 0, createdAt: Date.now() }; await kv.set(["users", u], newUser); return c.redirect("/login"); });
app.get("/logout", (c) => { deleteCookie(c, "auth"); return c.redirect("/login"); });
app.get("/change-password", (c) => c.html(<Layout title="Change Password"><div class="max-w-sm mx-auto mt-20 glass p-8 rounded-xl"><h1 class="text-xl font-bold mb-4">စကားဝှက်ပြောင်းမည်</h1><form action="/change-password" method="post" class="space-y-4"><input type="password" name="newpass" placeholder="New Password" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white" /><button class="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-bold">အတည်ပြုမည်</button></form><a href="/" class="block text-center mt-4 text-xs text-gray-400">Back</a></div></Layout>));
app.post("/change-password", async (c) => { const cookie = getCookie(c, "auth"); const user = await getUser(cookie || ""); if(!user) return c.redirect("/login"); const { newpass } = await c.req.parseBody(); if(String(newpass).length < 6) return c.text("Min 6 chars"); user.passwordHash = await hashPassword(String(newpass)); await kv.set(["users", user.username], user); return c.html(<Layout><div class="text-center mt-20"><p class="text-green-500 text-xl font-bold mb-4">Success!</p><a href="/" class="bg-zinc-800 px-4 py-2 rounded-lg text-sm">Home</a></div></Layout>); });
Deno.cron("Cleanup", "0 * * * *", async () => { const now = Date.now(); const iter = kv.list<FileData>({ prefix: ["files"] }); for await (const entry of iter) { const file = entry.value; if (file.expiresAt > 0 && file.expiresAt < now) { await deleteFileFromR2(file); const username = entry.key[1] as string; const uRes = await kv.get<User>(["users", username]); if (uRes.value) { const u = uRes.value; await kv.atomic().delete(entry.key).set(["users", username], { ...u, usedStorage: Math.max(0, u.usedStorage - file.sizeBytes) }).commit(); } else { await kv.delete(entry.key); } } } });

Deno.serve(app.fetch);
