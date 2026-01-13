/** @jsxImportSource npm:hono@4/jsx */
import { Hono } from "npm:hono@4";
import { getCookie, setCookie, deleteCookie } from "npm:hono@4/cookie";
import { S3Client, PutObjectCommand, DeleteObjectCommand } from "npm:@aws-sdk/client-s3";

const app = new Hono();
const kv = await Deno.openKv();

// =======================
// 1. CONFIG & CONSTANTS
// =======================
const ADMIN_USERNAME = "admin";
const SALT = "my-secret-salt";
const FREE_STORAGE_LIMIT = 200 * 1024 * 1024; // 200 MB
const FREE_UPLOAD_LIMIT = 20 * 1024 * 1024;   // 20 MB

const s3Server1 = new S3Client({
  region: "auto",
  endpoint: `https://${Deno.env.get("R2_1_ACCOUNT_ID")}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: Deno.env.get("R2_1_ACCESS_KEY_ID")!,
    secretAccessKey: Deno.env.get("R2_1_SECRET_ACCESS_KEY")!,
  },
});

const s3Server2 = new S3Client({
  region: "auto",
  endpoint: `https://${Deno.env.get("R2_2_ACCOUNT_ID")}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: Deno.env.get("R2_2_ACCESS_KEY_ID")!,
    secretAccessKey: Deno.env.get("R2_2_SECRET_ACCESS_KEY")!,
  },
});

const DOMAIN_1 = "https://lugyicloud.vercel.app/api/12/";
const DOMAIN_2 = "https://abc-iqowoq-clouding.vercel.app/api/1/";

// =======================
// 2. TYPES & HELPERS
// =======================
interface User { 
    username: string; 
    passwordHash: string; 
    isVip: boolean;
    vipExpiry?: number;
    usedStorage: number;
    createdAt: number;
}

interface FileData { 
    id: string; 
    name: string; 
    sizeBytes: number;
    size: string;
    server: "1" | "2"; 
    r2Key: string;
    downloadUrl: string; 
    uploadedAt: number;
    expiresAt: number;
    type: "image" | "video" | "other";
    isVipFile: boolean;
}

async function hashPassword(text: string) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text + SALT);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getUser(username: string) { 
    const res = await kv.get<User>(["users", username]); 
    return res.value; 
}

function checkVipStatus(user: User): boolean {
    if (!user.vipExpiry) return false;
    return user.vipExpiry > Date.now();
}

// 🔥 DATE FORMATTER (13 Jan 2026)
function formatDate(ts: number) {
    return new Date(ts).toLocaleDateString('en-GB', {
        day: 'numeric', month: 'short', year: 'numeric'
    });
}

// =======================
// 3. UI SCRIPTS & STYLES
// =======================
const mainScript = `
<script>
    function switchTab(tab) {
        document.querySelectorAll('.file-item').forEach(el => el.classList.add('hidden'));
        document.querySelectorAll('.tab-btn').forEach(el => {
            el.classList.remove('bg-yellow-500', 'text-black');
            el.classList.add('bg-zinc-800', 'text-gray-400');
        });
        
        document.getElementById('btn-' + tab).classList.remove('bg-zinc-800', 'text-gray-400');
        document.getElementById('btn-' + tab).classList.add('bg-yellow-500', 'text-black');
        
        if(tab === 'all') document.querySelectorAll('.file-item').forEach(el => el.classList.remove('hidden'));
        else document.querySelectorAll('.type-' + tab).forEach(el => el.classList.remove('hidden'));
    }

    function uploadFile(event) {
        event.preventDefault();
        const form = document.getElementById('uploadForm');
        const fileInput = document.getElementById('fileInput');
        
        if(fileInput.files.length === 0) { alert("ဖိုင်ရွေးပါ"); return; }

        // Front-end Limit Check (For UX)
        const isVip = document.body.dataset.vip === "true";
        const file = fileInput.files[0];
        if(!isVip && file.size > 20 * 1024 * 1024) {
            alert("Free User များသည် 20MB အောက်ဖိုင်များကိုသာ တင်ခွင့်ရှိသည်။");
            return;
        }

        const formData = new FormData(form);
        const xhr = new XMLHttpRequest();
        
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const progressContainer = document.getElementById('progressContainer');
        const submitBtn = document.getElementById('submitBtn');

        progressContainer.classList.remove('hidden');
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';

        xhr.upload.addEventListener("progress", (e) => {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = percent + "%";
                progressText.innerText = percent + "%";
            }
        });

        xhr.onload = () => {
            if (xhr.status === 200) {
                progressBar.classList.remove('bg-yellow-500');
                progressBar.classList.add('bg-green-500');
                submitBtn.innerHTML = '<i class="fa-solid fa-check"></i> ပြီးပါပြီ!';
                setTimeout(() => window.location.reload(), 1000);
            } else {
                alert("Upload Failed: " + xhr.responseText);
                submitBtn.disabled = false;
                submitBtn.innerText = "တင်မည်";
                progressContainer.classList.add('hidden');
            }
        };
        xhr.onerror = () => { alert("Connection Error"); submitBtn.disabled = false; };
        xhr.open("POST", "/upload");
        xhr.send(formData);
    }
</script>
`;

const Layout = (props: { children: any; title?: string; user?: User | null }) => (
    <html>
        <head>
            <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>{props.title || "Gold Storage Pro"}</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" />
            <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap" rel="stylesheet" />
            <style>{`
                body { font-family: 'Padauk', sans-serif; background-color: #09090b; color: #e4e4e7; }
                .glass { background: rgba(39, 39, 42, 0.6); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.05); }
                .custom-scroll::-webkit-scrollbar { width: 6px; }
                .custom-scroll::-webkit-scrollbar-track { background: #18181b; }
                .custom-scroll::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 3px; }
                .custom-scroll::-webkit-scrollbar-thumb:hover { background: #52525b; }
            `}</style>
        </head>
        <body data-vip={props.user && checkVipStatus(props.user) ? "true" : "false"}>
            <nav class="fixed top-0 w-full z-50 glass border-b border-zinc-800">
                <div class="max-w-5xl mx-auto px-4 py-3 flex justify-between items-center">
                    <a href="/" class="text-xl font-black text-transparent bg-clip-text bg-gradient-to-r from-yellow-400 to-yellow-600 italic tracking-tighter">
                        <i class="fa-solid fa-cube text-yellow-500 mr-2"></i>GOLD STORAGE
                    </a>
                    {props.user ? (
                        <div class="flex gap-3 items-center">
                            <div class="hidden sm:flex flex-col items-end leading-tight">
                                <span class="text-xs font-bold text-gray-300">{props.user.username}</span>
                                {checkVipStatus(props.user) ? (
                                    <span class="text-[9px] text-yellow-500 font-bold tracking-wider">VIP MEMBER</span>
                                ) : (
                                    <span class="text-[9px] text-gray-500 font-bold tracking-wider">FREE MEMBER</span>
                                )}
                            </div>
                            {props.user.username === ADMIN_USERNAME && <a href="/admin" class="w-8 h-8 flex items-center justify-center bg-purple-600 rounded-full hover:bg-purple-500 transition"><i class="fa-solid fa-shield-halved text-xs"></i></a>}
                            <a href="/logout" class="w-8 h-8 flex items-center justify-center bg-zinc-800 border border-zinc-700 rounded-full hover:bg-red-600/20 hover:text-red-500 hover:border-red-500/50 transition"><i class="fa-solid fa-power-off text-xs"></i></a>
                        </div>
                    ) : (
                        <a href="/login" class="text-xs bg-yellow-500 text-black px-4 py-2 rounded-full font-bold hover:bg-yellow-400 transition">ဝင်မည်</a>
                    )}
                </div>
            </nav>
            <main class="pt-20 pb-10 px-4 max-w-5xl mx-auto">{props.children}</main>
            <div dangerouslySetInnerHTML={{__html: mainScript}} />
        </body>
    </html>
);

// =======================
// 4. ROUTES
// =======================

app.get("/", async (c) => {
    const cookie = getCookie(c, "auth");
    if(!cookie) return c.redirect("/login");
    const user = await getUser(cookie);
    if(!user) return c.redirect("/login");

    const isVip = checkVipStatus(user);
    const iter = kv.list<FileData>({ prefix: ["files", user.username] }, { reverse: true });
    const files = [];
    let totalBytes = 0;

    for await (const res of iter) {
        files.push(res.value);
        totalBytes += res.value.sizeBytes;
    }

    const totalMB = (totalBytes / 1024 / 1024).toFixed(2);
    // Limit Logic: VIP = Unlimited, Free = 200MB
    const limitBytes = isVip ? 1000 * 1024 * 1024 * 1024 * 1024 : FREE_STORAGE_LIMIT; 
    const displayLimit = isVip ? "∞" : "200 MB";
    const usedPercent = Math.min(100, (totalBytes / limitBytes) * 100);

    return c.html(
        <Layout user={user}>
            
            {/* STATS & INFO */}
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                {/* Profile Card */}
                <div class="glass p-5 rounded-2xl relative overflow-hidden group">
                    <div class="absolute top-0 right-0 p-4 opacity-10 group-hover:scale-110 transition"><i class="fa-solid fa-id-card text-6xl text-white"></i></div>
                    <p class="text-xs text-zinc-400 uppercase font-bold mb-1">အကောင့်အမျိုးအစား</p>
                    <p class={`text-2xl font-black ${isVip ? 'text-yellow-500 drop-shadow-md' : 'text-zinc-300'}`}>
                        {isVip ? "VIP PRO" : "Free Plan"}
                    </p>
                    {isVip && user.vipExpiry && (
                        <p class="text-[10px] text-green-400 mt-2 font-mono bg-green-900/20 inline-block px-2 py-1 rounded">
                            EXP: {formatDate(user.vipExpiry)}
                        </p>
                    )}
                    <a href="/change-password" class="absolute bottom-4 right-4 text-xs text-zinc-500 hover:text-white transition"><i class="fa-solid fa-key mr-1"></i> Pass</a>
                </div>

                {/* Storage Card */}
                <div class="glass p-5 rounded-2xl relative">
                    <div class="flex justify-between items-end mb-2">
                        <div>
                            <p class="text-xs text-zinc-400 uppercase font-bold">Storage</p>
                            <p class="text-xl font-bold text-white">{totalMB} <span class="text-sm text-zinc-500">/ {displayLimit}</span></p>
                        </div>
                        <span class="text-2xl font-black text-zinc-600">{usedPercent.toFixed(0)}%</span>
                    </div>
                    <div class="w-full bg-zinc-800 rounded-full h-3 overflow-hidden">
                        <div class={`h-full rounded-full ${isVip ? 'bg-gradient-to-r from-yellow-600 to-yellow-400' : 'bg-zinc-500'}`} style={`width: ${usedPercent}%`}></div>
                    </div>
                </div>

                {/* File Count */}
                <div class="glass p-5 rounded-2xl flex items-center justify-between">
                    <div>
                        <p class="text-xs text-zinc-400 uppercase font-bold">ဖိုင်စုစုပေါင်း</p>
                        <p class="text-3xl font-black text-white">{files.length}</p>
                    </div>
                    <div class="w-12 h-12 rounded-xl bg-blue-500/10 flex items-center justify-center text-blue-500 text-2xl">
                        <i class="fa-solid fa-folder-open"></i>
                    </div>
                </div>
            </div>

            {/* UPLOAD AREA */}
            <div class="glass p-6 rounded-2xl mb-8 border border-zinc-700/50 shadow-2xl">
                <h2 class="font-bold text-lg mb-6 flex items-center gap-2 text-white">
                    <span class="bg-blue-600 w-8 h-8 rounded-lg flex items-center justify-center text-sm"><i class="fa-solid fa-cloud-arrow-up"></i></span>
                    ဖိုင်အသစ် တင်ရန်
                </h2>
                
                <form id="uploadForm" onsubmit="uploadFile(event)" class="space-y-5">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                        <div>
                            <label class="text-xs font-bold text-zinc-400 uppercase mb-2 block">ဖိုင်နာမည် (Optional)</label>
                            <input name="customName" placeholder="File Name..." class="w-full bg-zinc-900 border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none transition" />
                        </div>
                        
                        {/* EXPIRY */}
                        <div>
                            <label class="text-xs font-bold text-zinc-400 uppercase mb-2 block">သက်တမ်း</label>
                            {isVip ? (
                                <select name="expiry" class="w-full bg-zinc-900 border border-yellow-600/50 rounded-xl p-3 text-sm text-yellow-500 font-bold focus:border-yellow-500 outline-none">
                                    <option value="0">Lifetime (မဖျက်ပါ)</option>
                                    <option value="7">1 Week</option>
                                    <option value="30">1 Month</option>
                                </select>
                            ) : (
                                <div class="relative">
                                    <input disabled value="1 Month (Free Limit)" class="w-full bg-zinc-900 border border-zinc-700 rounded-xl p-3 text-sm text-zinc-500 cursor-not-allowed" />
                                    <input type="hidden" name="expiry" value="30" />
                                    <i class="fa-solid fa-lock absolute right-4 top-3.5 text-zinc-600"></i>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* SERVER SELECT */}
                    <div class="grid grid-cols-2 gap-4">
                        <label class="cursor-pointer relative">
                            <input type="radio" name="server" value="1" class="peer sr-only" checked />
                            <div class="p-3 bg-zinc-900 border border-zinc-700 rounded-xl peer-checked:border-blue-500 peer-checked:bg-blue-500/10 text-center transition hover:bg-zinc-800">
                                <span class="font-bold text-sm block text-gray-300 peer-checked:text-white">Server 1</span>
                            </div>
                        </label>
                        <label class="cursor-pointer relative">
                            <input type="radio" name="server" value="2" class="peer sr-only" />
                            <div class="p-3 bg-zinc-900 border border-zinc-700 rounded-xl peer-checked:border-yellow-500 peer-checked:bg-yellow-500/10 text-center transition hover:bg-zinc-800">
                                <span class="font-bold text-sm block text-gray-300 peer-checked:text-white">Server 2</span>
                            </div>
                        </label>
                    </div>

                    {/* FILE INPUT */}
                    <div class="border-2 border-dashed border-zinc-700 rounded-2xl p-8 text-center hover:border-yellow-500/50 hover:bg-zinc-800/50 transition cursor-pointer group relative">
                        <input type="file" id="fileInput" name="file" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"/>
                        <div class="space-y-2">
                            <div class="w-12 h-12 bg-zinc-800 rounded-full flex items-center justify-center mx-auto text-zinc-400 group-hover:text-yellow-500 transition"><i class="fa-solid fa-plus text-xl"></i></div>
                            <p class="text-sm font-bold text-zinc-300">Click to upload file</p>
                            <p class="text-[10px] text-zinc-500">
                                {isVip ? "Max Size: Unlimited" : "Max Size: 20MB"}
                            </p>
                        </div>
                    </div>

                    {/* PROGRESS */}
                    <div id="progressContainer" class="hidden">
                        <div class="flex justify-between text-[10px] uppercase font-bold text-zinc-400 mb-1">
                            <span>Uploading...</span><span id="progressText">0%</span>
                        </div>
                        <div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden">
                            <div id="progressBar" class="bg-yellow-500 h-full rounded-full transition-all duration-300" style="width: 0%"></div>
                        </div>
                    </div>

                    <button id="submitBtn" class="w-full bg-gradient-to-r from-yellow-600 to-yellow-500 text-black font-bold py-3.5 rounded-xl shadow-lg hover:brightness-110 transition active:scale-95">
                        တင်မည်
                    </button>
                </form>
            </div>

            {/* FILE LIST SECTION */}
            <div class="flex items-center justify-between mb-4">
                <h3 class="font-bold text-white text-sm uppercase tracking-wide">
                    <i class="fa-solid fa-list-ul mr-2 text-zinc-500"></i> My Files
                </h3>
                <div class="flex bg-zinc-900 p-1 rounded-lg">
                    <button id="btn-all" onclick="switchTab('all')" class="tab-btn px-3 py-1 text-[10px] font-bold rounded-md bg-yellow-500 text-black transition">ALL</button>
                    <button id="btn-video" onclick="switchTab('video')" class="tab-btn px-3 py-1 text-[10px] font-bold rounded-md text-gray-400 hover:text-white transition">VIDEO</button>
                    <button id="btn-image" onclick="switchTab('image')" class="tab-btn px-3 py-1 text-[10px] font-bold rounded-md text-gray-400 hover:text-white transition">IMG</button>
                </div>
            </div>

            {/* SCROLLABLE FILE LIST CONTAINER */}
            <div class="glass rounded-2xl overflow-hidden border border-zinc-700/50">
                <div class="max-h-[500px] overflow-y-auto custom-scroll p-2 space-y-2">
                    {files.map(f => (
                        <div class={`file-item type-${f.type} bg-zinc-800/50 hover:bg-zinc-800 p-3 rounded-xl flex justify-between items-center group transition border border-transparent hover:border-zinc-600`}>
                            <div class="flex items-center gap-4 overflow-hidden">
                                <div class={`w-10 h-10 rounded-lg flex items-center justify-center text-lg flex-shrink-0 ${f.type === 'image' ? 'bg-yellow-500/10 text-yellow-500' : f.type === 'video' ? 'bg-blue-500/10 text-blue-500' : 'bg-zinc-700 text-zinc-400'}`}>
                                    <i class={`fa-solid ${f.type === 'image' ? 'fa-image' : f.type === 'video' ? 'fa-clapperboard' : 'fa-file'}`}></i>
                                </div>
                                <div class="min-w-0">
                                    <p class="font-bold text-sm truncate text-zinc-200 group-hover:text-white transition">{f.name}</p>
                                    <div class="flex items-center gap-3 text-[10px] text-zinc-500 font-mono mt-0.5">
                                        <span class="bg-zinc-900 px-1.5 rounded text-zinc-400">{f.size}</span>
                                        <span>{formatDate(f.uploadedAt)}</span>
                                        {f.expiresAt > 0 ? (
                                            <span class="text-red-400 bg-red-900/10 px-1.5 rounded">Exp: {formatDate(f.expiresAt)}</span>
                                        ) : (
                                            <span class="text-green-500 bg-green-900/10 px-1.5 rounded">Lifetime</span>
                                        )}
                                    </div>
                                </div>
                            </div>
                            <div class="flex gap-2 opacity-80 group-hover:opacity-100 transition">
                                <a href={f.downloadUrl} target="_blank" class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-blue-600 text-white rounded-lg transition"><i class="fa-solid fa-download text-xs"></i></a>
                                <button onclick={`navigator.clipboard.writeText('${f.downloadUrl}'); this.innerHTML='<i class="fa-solid fa-check"></i>'; setTimeout(()=>this.innerHTML='<i class="fa-regular fa-copy"></i>', 1000)`} class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-green-600 text-white rounded-lg transition"><i class="fa-regular fa-copy text-xs"></i></button>
                                <form action={`/delete/${f.id}`} method="post" onsubmit="return confirm('ဖျက်မှာသေချာလား?')"><button class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-red-600 text-white rounded-lg transition"><i class="fa-solid fa-trash text-xs"></i></button></form>
                            </div>
                        </div>
                    ))}
                    {files.length === 0 && (
                        <div class="text-center text-zinc-500 py-12 flex flex-col items-center">
                            <i class="fa-solid fa-folder-open text-4xl mb-3 opacity-20"></i>
                            <p class="text-sm">ဖိုင်များ မရှိသေးပါ။</p>
                        </div>
                    )}
                </div>
            </div>
        </Layout>
    );
});

// 🔥 UPLOAD HANDLER
app.post("/upload", async (c) => {
    const cookie = getCookie(c, "auth");
    if(!cookie) return c.text("Unauthorized", 401);
    const user = await getUser(cookie);
    if(!user) return c.text("Login required", 401);

    const isVip = checkVipStatus(user);
    const body = await c.req.parseBody();
    const file = body['file'];
    const serverChoice = String(body['server']);
    const customName = String(body['customName']).trim();
    let expiryDays = parseInt(String(body['expiry'])) || 30;

    // 🔥 LIMIT CHECK (BACKEND)
    if (!isVip) {
        // Free User Constraints
        expiryDays = 30; 
        if (file.size > FREE_UPLOAD_LIMIT) return c.text("Free Limit: Max 20MB per file", 400);
        if (user.usedStorage + file.size > FREE_STORAGE_LIMIT) return c.text("Storage Full! (Free 200MB Limit)", 400);
    } 

    if (file instanceof File) {
        try {
            let finalName = file.name;
            if (customName) {
                const ext = file.name.split('.').pop();
                finalName = customName.endsWith('.' + ext) ? customName : customName + '.' + ext;
            }
            const safeName = finalName.replace(/[^a-zA-Z0-9.-]/g, "_");
            const r2Key = `${user.username}/${crypto.randomUUID()}-${safeName}`;

            let type: any = "other";
            if (file.type.startsWith("image/")) type = "image";
            else if (file.type.startsWith("video/")) type = "video";

            const client = serverChoice === "1" ? s3Server1 : s3Server2;
            const bucket = serverChoice === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");

            await client.send(new PutObjectCommand({
                Bucket: bucket, Key: r2Key, Body: new Uint8Array(await file.arrayBuffer()), ContentType: file.type,
            }));

            const finalUrl = serverChoice === "1" ? `${DOMAIN_1}${r2Key}` : `${DOMAIN_2}${r2Key}`;
            
            const fileData: FileData = {
                id: crypto.randomUUID(),
                name: finalName,
                size: (file.size / 1024 / 1024).toFixed(2) + " MB",
                sizeBytes: file.size,
                server: serverChoice as "1" | "2",
                r2Key: r2Key,
                downloadUrl: finalUrl,
                uploadedAt: Date.now(),
                type: type,
                expiresAt: expiryDays > 0 ? Date.now() + (expiryDays * 86400000) : 0,
                isVipFile: isVip && expiryDays === 0
            };

            await kv.set(["files", user.username, fileData.id], fileData);
            user.usedStorage += file.size;
            await kv.set(["users", user.username], user);

            return c.text("Success");
        } catch (e: any) { return c.text("Upload Failed: " + e.message, 500); }
    }
    return c.text("No file", 400);
});

// 🔥 CRON JOB (DELETE EXPIRED)
app.get("/api/cron/cleanup", async (c) => {
    const usersIter = kv.list<User>({ prefix: ["users"] });
    let deletedCount = 0;
    const now = Date.now();

    for await (const u of usersIter) {
        const user = u.value;
        const filesIter = kv.list<FileData>({ prefix: ["files", user.username] });
        let updatedStorage = user.usedStorage;
        let userUpdated = false;

        // Check VIP Expiry & Grace Period
        if (user.vipExpiry && user.vipExpiry < now) {
            const gracePeriodEnd = user.vipExpiry + (7 * 86400000); // 7 Days Grace
            if (now > gracePeriodEnd) {
                user.isVip = false;
                user.vipExpiry = undefined;
                userUpdated = true;
                // Delete VIP lifetime files
                for await (const f of filesIter) {
                    if (f.value.isVipFile || f.value.expiresAt === 0) {
                        await deleteFileFromR2(f.value);
                        await kv.delete(f.key);
                        updatedStorage = Math.max(0, updatedStorage - f.value.sizeBytes);
                        deletedCount++;
                    }
                }
            }
        }

        // Check Normal Expiry
        const filesIter2 = kv.list<FileData>({ prefix: ["files", user.username] });
        for await (const f of filesIter2) {
            if (f.value.expiresAt > 0 && f.value.expiresAt < now) {
                await deleteFileFromR2(f.value);
                await kv.delete(f.key);
                updatedStorage = Math.max(0, updatedStorage - f.value.sizeBytes);
                deletedCount++;
                userUpdated = true;
            }
        }
        
        if (updatedStorage !== user.usedStorage || userUpdated) {
            user.usedStorage = updatedStorage;
            await kv.set(u.key, user);
        }
    }
    return c.json({ deleted: deletedCount });
});

async function deleteFileFromR2(f: FileData) {
    const client = f.server === "1" ? s3Server1 : s3Server2;
    const bucket = f.server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    try { await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: f.r2Key })); } catch (e) { console.error(e); }
}

app.post("/delete/:id", async (c) => {
    const cookie = getCookie(c, "auth");
    const user = await getUser(cookie || "");
    if(!user) return c.redirect("/login");
    const id = c.req.param("id");
    const fileRes = await kv.get<FileData>(["files", user.username, id]);
    if (fileRes.value) {
        await deleteFileFromR2(fileRes.value);
        await kv.delete(["files", user.username, id]);
        user.usedStorage = Math.max(0, user.usedStorage - fileRes.value.sizeBytes);
        await kv.set(["users", user.username], user);
    }
    return c.redirect("/");
});

// AUTH & ADMIN
app.get("/login", (c) => c.html(<Layout title="Login"><div class="max-w-sm mx-auto mt-24 glass p-8 rounded-2xl border border-zinc-700"><h1 class="text-3xl font-black mb-2 text-center text-yellow-500 italic">GOLD STORAGE</h1><p class="text-center text-zinc-500 text-xs mb-8">လုံခြုံစိတ်ချရသော Cloud Storage</p><form action="/login" method="post" class="space-y-4"><input name="username" placeholder="အမည် (Username)" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white focus:border-yellow-500 outline-none" /><input type="password" name="password" placeholder="စကားဝှက် (Password)" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white focus:border-yellow-500 outline-none" /><button class="w-full bg-gradient-to-r from-yellow-600 to-yellow-500 text-black font-bold py-3 rounded-xl hover:brightness-110">ဝင်မည်</button></form><p class="text-center text-xs mt-6 text-zinc-500">အကောင့်မရှိဘူးလား? <a href="/register" class="text-yellow-500 font-bold hover:underline">အကောင့်သစ်ဖွင့်မယ်</a></p></div></Layout>));
app.post("/login", async (c) => {
    const { username, password } = await c.req.parseBody();
    const u = String(username).trim();
    const user = await getUser(u);
    if (user && user.passwordHash === await hashPassword(String(password).trim())) { setCookie(c, "auth", u, { path: "/", maxAge: 86400 * 30 }); return c.redirect("/"); }
    return c.html(<Layout><p class="text-center text-red-500 mt-20">မှားယွင်းနေပါသည်။</p></Layout>);
});
app.get("/register", (c) => c.html(<Layout title="Register"><div class="max-w-sm mx-auto mt-24 glass p-8 rounded-2xl border border-zinc-700"><h1 class="text-xl font-bold mb-6 text-center text-white">အကောင့်သစ်ဖွင့်မည်</h1><form action="/register" method="post" class="space-y-4"><input name="username" placeholder="Username" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white" /><input type="password" name="password" placeholder="Password" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white" /><button class="w-full bg-green-600 hover:bg-green-500 py-3 rounded-xl font-bold">စာရင်းသွင်းမည်</button></form></div></Layout>));
app.post("/register", async (c) => {
    const { username, password } = await c.req.parseBody();
    const u = String(username).trim();
    if (await getUser(u)) return c.html(<Layout><p class="text-center text-red-500 mt-20">Username ရှိပြီးသားဖြစ်နေသည်။</p></Layout>);
    const newUser: User = { username: u, passwordHash: await hashPassword(String(password)), isVip: false, usedStorage: 0, createdAt: Date.now() };
    await kv.set(["users", u], newUser);
    return c.redirect("/login");
});
app.get("/logout", (c) => { deleteCookie(c, "auth"); return c.redirect("/login"); });

// ADMIN PANEL
app.get("/admin", async (c) => {
    const cookie = getCookie(c, "auth");
    if(cookie !== ADMIN_USERNAME) return c.redirect("/");
    const iter = kv.list<User>({ prefix: ["users"] });
    const users = []; for await (const res of iter) users.push(res.value);
    return c.html(
        <Layout title="Admin Panel" user={{ username: ADMIN_USERNAME, isVip: true } as any}>
            <div class="glass p-6 rounded-2xl border border-zinc-700">
                <h1 class="text-2xl font-bold mb-6 flex items-center gap-2"><i class="fa-solid fa-users-gear text-purple-500"></i> User Management</h1>
                <div class="space-y-4">
                    {users.map(u => (
                        <div class="bg-zinc-800/50 p-4 rounded-xl border border-zinc-700 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                            <div>
                                <p class="font-bold text-white flex items-center gap-2">
                                    {u.username} 
                                    {checkVipStatus(u) ? <span class="bg-yellow-500 text-black px-1.5 rounded text-[10px] font-bold">VIP</span> : <span class="bg-zinc-600 px-1.5 rounded text-[10px]">FREE</span>}
                                </p>
                                <p class="text-xs text-gray-400 mt-1">Used: {(u.usedStorage/1024/1024).toFixed(2)} MB</p>
                                {u.vipExpiry && <p class="text-[10px] text-green-400 mt-0.5">Exp: {formatDate(u.vipExpiry)}</p>}
                            </div>
                            <form action="/admin/add-vip" method="post" class="flex gap-2">
                                <input type="hidden" name="username" value={u.username} />
                                <select name="days" class="bg-zinc-900 text-xs p-2 rounded-lg border border-zinc-600 outline-none focus:border-purple-500">
                                    <option value="30">Add 1 Month</option>
                                    <option value="90">Add 3 Months</option>
                                    <option value="365">Add 1 Year</option>
                                    <option value="-1">Remove VIP</option>
                                </select>
                                <button class="bg-purple-600 hover:bg-purple-500 px-4 py-2 rounded-lg text-xs font-bold transition shadow-lg">Save</button>
                            </form>
                        </div>
                    ))}
                </div>
            </div>
        </Layout>
    );
});

app.post("/admin/add-vip", async (c) => {
    const cookie = getCookie(c, "auth");
    if(cookie !== ADMIN_USERNAME) return c.text("Unauthorized", 403);
    const { username, days } = await c.req.parseBody();
    const user = await getUser(String(username));
    
    if(user) {
        const addDays = parseInt(String(days));
        if (addDays === -1) {
            user.isVip = false;
            user.vipExpiry = undefined;
        } else {
            user.isVip = true;
            const now = Date.now();
            const currentExp = (user.vipExpiry && user.vipExpiry > now) ? user.vipExpiry : now;
            user.vipExpiry = currentExp + (addDays * 24 * 60 * 60 * 1000);
        }
        await kv.set(["users", user.username], user);
    }
    return c.redirect("/admin");
});

Deno.serve(app.fetch);
