/** @jsxImportSource npm:hono@4/jsx */
import { Hono } from "npm:hono@4";
import { getCookie, setCookie, deleteCookie } from "npm:hono@4/cookie";
import { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand } from "npm:@aws-sdk/client-s3";
import { getSignedUrl } from "npm:@aws-sdk/s3-request-presigner";

const app = new Hono();
const kv = await Deno.openKv();

// =======================
// 1. CONFIG
// =======================
const ADMIN_USERNAME = "soekyawwin";
// Security အတွက် Password Hashing မှာသုံးမယ့် Key (env ထဲထည့်သင့်ပါတယ်)
const SECRET_KEY = Deno.env.get("SECRET_SALT") || "change-this-secret-salt-complex-string";

// Storage Quota
const FREE_STORAGE_LIMIT = 200 * 1024 * 1024; // 200 MB
const VIP_STORAGE_LIMIT = 5 * 1024 * 1024 * 1024; // 5 GB (Direct Upload မို့ ပိုပေးလို့ရပြီ)

// S3 Clients
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

// =======================
// 2. HELPERS (Security & Logic)
// =======================
interface User { username: string; passwordHash: string; isVip: boolean; vipExpiry?: number; usedStorage: number; createdAt: number; }
interface FileData { id: string; name: string; sizeBytes: number; size: string; server: "1" | "2"; r2Key: string; uploadedAt: number; expiresAt: number; type: "image" | "video" | "other"; isVipFile: boolean; }

// Better Security using PBKDF2
async function hashPassword(password: string) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]);
    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: enc.encode(SECRET_KEY), iterations: 100000, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    const exported = await crypto.subtle.exportKey("raw", key);
    return Array.from(new Uint8Array(exported)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getUser(username: string) { const res = await kv.get<User>(["users", username]); return res.value; }
function checkVipStatus(user: User): boolean { return user.vipExpiry ? user.vipExpiry > Date.now() : false; }
function formatDate(ts: number) { return new Date(ts).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }); }

// =======================
// 3. UI (Direct Upload Script)
// =======================
const mainScript = `
<script>
    let currentCursor = null;

    function switchTab(tab) {
        const url = new URL(window.location);
        url.searchParams.set('type', tab);
        url.searchParams.delete('cursor'); // Reset cursor on tab switch
        window.location.href = url.toString();
    }

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

    async function uploadFile(event) {
        event.preventDefault();
        const fileInput = document.getElementById('fileInput');
        const submitBtn = document.getElementById('submitBtn');
        const progressBar = document.getElementById('progressBar');
        const progressContainer = document.getElementById('progressContainer');
        const progressText = document.getElementById('progressText');
        const form = document.getElementById('uploadForm');

        if(fileInput.files.length === 0) { alert("ဖိုင်ရွေးပါ"); return; }
        const file = fileInput.files[0];

        // 1. Get Presigned URL
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Getting Permission...';
        progressContainer.classList.remove('hidden');

        try {
            const formData = new FormData(form);
            const presignRes = await fetch("/api/upload/presign", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    name: file.name,
                    type: file.type,
                    size: file.size,
                    server: formData.get("server"),
                    expiry: formData.get("expiry"),
                    customName: formData.get("customName")
                })
            });

            if (!presignRes.ok) throw new Error(await presignRes.text());
            const { url, key, fileId } = await presignRes.json();

            // 2. Direct Upload to R2 (PUT)
            submitBtn.innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Uploading to Cloud...';
            
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
                    // 3. Notify Server to Save Metadata
                    submitBtn.innerHTML = 'Saving...';
                    await fetch("/api/upload/complete", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ key, fileId, server: formData.get("server") })
                    });

                    progressBar.classList.add('bg-green-500');
                    submitBtn.innerHTML = '<i class="fa-solid fa-check"></i> Done!';
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    throw new Error("Upload failed");
                }
            };
            xhr.onerror = () => { throw new Error("Network Error"); };
            xhr.send(file);

        } catch (error) {
            alert(error.message);
            submitBtn.disabled = false;
            submitBtn.innerText = "ပြန်ကြိုးစားပါ";
            progressContainer.classList.add('hidden');
        }
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
            <style>{`body { font-family: 'Padauk', sans-serif; background-color: #09090b; color: #e4e4e7; } .glass { background: rgba(39, 39, 42, 0.6); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.05); } .custom-scroll::-webkit-scrollbar { width: 6px; } .custom-scroll::-webkit-scrollbar-track { background: #18181b; } .custom-scroll::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 3px; }`}</style>
        </head>
        <body data-vip={props.user && checkVipStatus(props.user) ? "true" : "false"}>
            <nav class="fixed top-0 w-full z-50 glass border-b border-zinc-800"><div class="max-w-5xl mx-auto px-4 py-3 flex justify-between items-center"><a href="/" class="text-xl font-black text-transparent bg-clip-text bg-gradient-to-r from-yellow-400 to-yellow-600 italic tracking-tighter"><i class="fa-solid fa-cube text-yellow-500 mr-2"></i>GOLD STORAGE</a>{props.user ? (<div class="flex gap-3 items-center"><div class="hidden sm:flex flex-col items-end leading-tight"><span class="text-xs font-bold text-gray-300">{props.user.username}</span>{checkVipStatus(props.user) ? <span class="text-[9px] text-yellow-500 font-bold">VIP</span> : <span class="text-[9px] text-gray-500 font-bold">FREE</span>}</div>{props.user.username === ADMIN_USERNAME && <a href="/admin" class="w-8 h-8 flex items-center justify-center bg-purple-600 rounded-full"><i class="fa-solid fa-shield-halved text-xs"></i></a>}<a href="/logout" class="w-8 h-8 flex items-center justify-center bg-zinc-800 border border-zinc-700 rounded-full hover:bg-red-600/20 hover:text-red-500"><i class="fa-solid fa-power-off text-xs"></i></a></div>) : (<a href="/login" class="text-xs bg-yellow-500 text-black px-4 py-2 rounded-full font-bold hover:bg-yellow-400 transition">ဝင်မည်</a>)}</div></nav>
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
    const filterType = c.req.query('type') || 'all';
    const cursor = c.req.query('cursor');

    // List files with Pagination (Limit 20) to save resources
    const iter = kv.list<FileData>({ prefix: ["files", user.username] }, { reverse: true, limit: 20, cursor: cursor });
    const files = [];
    let nextCursor = "";
    
    for await (const res of iter) {
        if (filterType === 'all' || res.value.type === filterType) {
            files.push(res.value);
        }
        nextCursor = res.cursor;
    }

    const totalMB = (user.usedStorage / 1024 / 1024).toFixed(2);
    const limitBytes = isVip ? VIP_STORAGE_LIMIT : FREE_STORAGE_LIMIT; 
    const displayLimit = isVip ? "5 GB" : "200 MB";
    const usedPercent = Math.min(100, (user.usedStorage / limitBytes) * 100);

    return c.html(<Layout user={user}>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <div class="glass p-5 rounded-2xl relative overflow-hidden group"><p class="text-xs text-zinc-400 uppercase font-bold mb-1">အကောင့်</p><p class={`text-2xl font-black ${isVip ? 'text-yellow-500' : 'text-zinc-300'}`}>{isVip ? "VIP PRO" : "Free Plan"}</p>{isVip && user.vipExpiry && <p class="text-[10px] text-green-400 mt-2 font-mono bg-green-900/20 inline-block px-2 py-1 rounded">EXP: {formatDate(user.vipExpiry)}</p>}<a href="/change-password" class="absolute bottom-4 right-4 text-xs text-zinc-500 hover:text-white transition"><i class="fa-solid fa-key mr-1"></i> Pass</a></div>
            <div class="glass p-5 rounded-2xl relative"><div class="flex justify-between items-end mb-2"><div><p class="text-xs text-zinc-400 uppercase font-bold">Storage</p><p class="text-xl font-bold text-white">{totalMB} <span class="text-sm text-zinc-500">/ {displayLimit}</span></p></div><span class="text-2xl font-black text-zinc-600">{usedPercent.toFixed(0)}%</span></div><div class="w-full bg-zinc-800 rounded-full h-3 overflow-hidden"><div class={`h-full rounded-full ${isVip ? 'bg-gradient-to-r from-yellow-600 to-yellow-400' : 'bg-zinc-500'}`} style={`width: ${usedPercent}%`}></div></div></div>
            <div class="glass p-5 rounded-2xl flex items-center justify-between"><div><p class="text-xs text-zinc-400 uppercase font-bold">Status</p><p class="text-sm font-bold text-green-500">Active</p></div><div class="w-12 h-12 rounded-xl bg-blue-500/10 flex items-center justify-center text-blue-500 text-2xl"><i class="fa-solid fa-signal"></i></div></div>
        </div>
        
        <div class="glass p-6 rounded-2xl mb-8 border border-zinc-700/50 shadow-2xl">
            <h2 class="font-bold text-lg mb-6 flex items-center gap-2 text-white"><span class="bg-blue-600 w-8 h-8 rounded-lg flex items-center justify-center text-sm"><i class="fa-solid fa-cloud-arrow-up"></i></span> Direct Upload</h2>
            <form id="uploadForm" onsubmit="uploadFile(event)" class="space-y-5">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                    <div><label class="text-xs font-bold text-zinc-400 uppercase mb-2 block">ဖိုင်နာမည် (Optional)</label><input name="customName" placeholder="File Name..." class="w-full bg-zinc-900 border border-zinc-700 rounded-xl p-3 text-sm focus:border-yellow-500 outline-none transition" /></div>
                    <div><label class="text-xs font-bold text-zinc-400 uppercase mb-2 block">သက်တမ်း</label>{isVip ? (<select name="expiry" class="w-full bg-zinc-900 border border-yellow-600/50 rounded-xl p-3 text-sm text-yellow-500 font-bold outline-none"><option value="0">Lifetime (မဖျက်ပါ)</option><option value="7">1 Week</option><option value="30">1 Month</option></select>) : (<div class="relative"><input disabled value="1 Month (Free Limit)" class="w-full bg-zinc-900 border border-zinc-700 rounded-xl p-3 text-sm text-zinc-500 cursor-not-allowed" /><input type="hidden" name="expiry" value="30" /><i class="fa-solid fa-lock absolute right-4 top-3.5 text-zinc-600"></i></div>)}</div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <label class="cursor-pointer relative"><input type="radio" name="server" value="1" class="peer sr-only" checked /><div class="p-3 bg-zinc-900 border border-zinc-700 rounded-xl peer-checked:border-blue-500 peer-checked:bg-blue-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-sm block text-gray-300 peer-checked:text-white">Server 1</span></div></label>
                    <label class="cursor-pointer relative"><input type="radio" name="server" value="2" class="peer sr-only" /><div class="p-3 bg-zinc-900 border border-zinc-700 rounded-xl peer-checked:border-yellow-500 peer-checked:bg-yellow-500/10 text-center transition hover:bg-zinc-800"><span class="font-bold text-sm block text-gray-300 peer-checked:text-white">Server 2</span></div></label>
                </div>
                <div class="border-2 border-dashed border-zinc-700 rounded-2xl p-8 text-center hover:border-yellow-500/50 hover:bg-zinc-800/50 transition cursor-pointer group relative">
                    <input type="file" id="fileInput" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"/>
                    <div class="space-y-2 pointer-events-none"><div class="w-12 h-12 bg-zinc-800 rounded-full flex items-center justify-center mx-auto text-zinc-400 group-hover:text-yellow-500 transition"><i id="uploadIcon" class="fa-solid fa-plus text-xl"></i></div><p id="fileNameDisplay" class="text-sm font-bold text-zinc-300 truncate px-4">ဖိုင်ရွေးချယ်ရန် နှိပ်ပါ</p><p class="text-[10px] text-zinc-500">{isVip ? "Unlimited Size (VIP)" : "Limit: 200MB / Total"}</p></div>
                </div>
                <div id="progressContainer" class="hidden"><div class="flex justify-between text-[10px] uppercase font-bold text-zinc-400 mb-1"><span>Uploading...</span><span id="progressText">0%</span></div><div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden"><div id="progressBar" class="bg-yellow-500 h-full rounded-full transition-all duration-300" style="width: 0%"></div></div></div>
                <button id="submitBtn" class="w-full bg-gradient-to-r from-yellow-600 to-yellow-500 text-black font-bold py-3.5 rounded-xl shadow-lg hover:brightness-110 transition active:scale-95">တင်မည်</button>
            </form>
        </div>

        <div class="flex items-center justify-between mb-4"><h3 class="font-bold text-white text-sm uppercase tracking-wide"><i class="fa-solid fa-list-ul mr-2 text-zinc-500"></i> My Files</h3><div class="flex bg-zinc-900 p-1 rounded-lg"><button onclick="switchTab('all')" class={`px-3 py-1 text-[10px] font-bold rounded-md transition ${filterType === 'all' ? 'bg-yellow-500 text-black' : 'text-gray-400'}`}>ALL</button><button onclick="switchTab('video')" class={`px-3 py-1 text-[10px] font-bold rounded-md transition ${filterType === 'video' ? 'bg-yellow-500 text-black' : 'text-gray-400'}`}>VIDEO</button><button onclick="switchTab('image')" class={`px-3 py-1 text-[10px] font-bold rounded-md transition ${filterType === 'image' ? 'bg-yellow-500 text-black' : 'text-gray-400'}`}>IMG</button></div></div>
        
        <div class="glass rounded-2xl overflow-hidden border border-zinc-700/50">
            <div class="max-h-[600px] overflow-y-auto custom-scroll p-2 space-y-2">
                {files.map(f => {
                    // Download Link Generation
                    const downloadLink = `/d/${f.server}/${f.r2Key}`;
                    return (
                    <div class={`bg-zinc-800/50 hover:bg-zinc-800 p-3 rounded-xl flex justify-between items-center group transition border border-transparent hover:border-zinc-600`}>
                        <div class="flex items-center gap-4 overflow-hidden">
                            <div class={`w-10 h-10 rounded-lg flex items-center justify-center text-lg flex-shrink-0 ${f.type === 'image' ? 'bg-yellow-500/10 text-yellow-500' : f.type === 'video' ? 'bg-blue-500/10 text-blue-500' : 'bg-zinc-700 text-zinc-400'}`}><i class={`fa-solid ${f.type === 'image' ? 'fa-image' : f.type === 'video' ? 'fa-clapperboard' : 'fa-file'}`}></i></div>
                            <div class="min-w-0"><p class="font-bold text-sm truncate text-zinc-200 group-hover:text-white transition">{f.name}</p><div class="flex items-center gap-3 text-[10px] text-zinc-500 font-mono mt-0.5"><span class="bg-zinc-900 px-1.5 rounded text-zinc-400">{f.size}</span><span>{formatDate(f.uploadedAt)}</span>{f.expiresAt > 0 ? (<span class="text-red-400 bg-red-900/10 px-1.5 rounded">Exp: {formatDate(f.expiresAt)}</span>) : (<span class="text-green-500 bg-green-900/10 px-1.5 rounded">Lifetime</span>)}</div></div>
                        </div>
                        <div class="flex gap-2 opacity-80 group-hover:opacity-100 transition">
                            <a href={downloadLink} target="_blank" class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-blue-600 text-white rounded-lg transition"><i class="fa-solid fa-download text-xs"></i></a>
                            <button onclick={`navigator.clipboard.writeText(window.location.origin + '${downloadLink}'); this.innerHTML='<i class="fa-solid fa-check"></i>'; setTimeout(()=>this.innerHTML='<i class="fa-regular fa-copy"></i>', 1000)`} class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-green-600 text-white rounded-lg transition"><i class="fa-regular fa-copy text-xs"></i></button>
                            <form action={`/delete/${f.id}`} method="post" onsubmit="return confirm('ဖျက်မှာသေချာလား?')"><button class="w-8 h-8 flex items-center justify-center bg-zinc-700 hover:bg-red-600 text-white rounded-lg transition"><i class="fa-solid fa-trash text-xs"></i></button></form>
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
// 5. API ROUTES (Direct Upload Logic)
// =======================

// A. Get Presigned URL (Frontend sends filename, Server gives permission)
app.post("/api/upload/presign", async (c) => {
    const cookie = getCookie(c, "auth");
    if(!cookie) return c.json({error: "Unauthorized"}, 401);
    const user = await getUser(cookie);
    if(!user) return c.json({error: "Login required"}, 401);

    const { name, size, server, type, customName, expiry } = await c.req.json();
    const isVip = checkVipStatus(user);
    const limitBytes = isVip ? VIP_STORAGE_LIMIT : FREE_STORAGE_LIMIT;

    if (user.usedStorage + size > limitBytes) {
        return c.json({ error: "Storage Limit Exceeded!" }, 400);
    }

    // Generate Safe Name
    let finalName = name;
    if (customName) {
        const ext = name.split('.').pop();
        finalName = customName.endsWith('.' + ext) ? customName : customName + '.' + ext;
    }
    const safeName = finalName.replace(/[^a-zA-Z0-9.-]/g, "_");
    const r2Key = `${user.username}/${crypto.randomUUID()}-${safeName}`;
    const fileId = crypto.randomUUID();

    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");

    // Generate Signed PUT URL (Valid for 15 mins)
    const command = new PutObjectCommand({ Bucket: bucket, Key: r2Key, ContentType: type });
    const url = await getSignedUrl(client, command, { expiresIn: 900 });

    return c.json({ url, key: r2Key, fileId });
});

// B. Upload Complete (Frontend tells server to save metadata)
app.post("/api/upload/complete", async (c) => {
    const cookie = getCookie(c, "auth");
    const user = await getUser(cookie || "");
    if(!user) return c.json({error: "Unauthorized"}, 401);

    const { key, fileId, server } = await c.req.json();
    const isVip = checkVipStatus(user);
    
    // Check actual size from R2? (Skipped for speed, trusting frontend size for now or need HeadObject)
    // Here we will assume success if client calls this. Ideally, do a HeadObject.
    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");
    
    try {
        const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key })); // Verify existence
        const sizeBytes = head.ContentLength || 0;
        
        const fileName = key.split("-").slice(1).join("-"); // Extract original name
        const type = head.ContentType?.startsWith("image/") ? "image" : head.ContentType?.startsWith("video/") ? "video" : "other";

        const expiryDays = isVip ? 0 : 30; // VIP default manual setting pending, simple logic for now

        const fileData: FileData = {
            id: fileId,
            name: fileName,
            sizeBytes: sizeBytes,
            size: (sizeBytes / 1024 / 1024).toFixed(2) + " MB",
            server: server,
            r2Key: key,
            uploadedAt: Date.now(),
            expiresAt: expiryDays > 0 ? Date.now() + (expiryDays * 86400000) : 0,
            type: type,
            isVipFile: isVip
        };

        // Atomic Transaction (Save File & Update User Storage)
        const res = await kv.atomic()
            .set(["files", user.username, fileId], fileData)
            .set(["users", user.username], { ...user, usedStorage: user.usedStorage + sizeBytes })
            .commit();

        return c.json({ success: true });
    } catch(e) {
        return c.json({ error: "Verification Failed" }, 500);
    }
});

// Need this import for verification
import { HeadObjectCommand } from "npm:@aws-sdk/client-s3";

// =======================
// 6. DOWNLOAD HANDLER (Redirect to Signed URL)
// =======================
// Example: /d/1/username/file-key
app.get("/d/:server/*", async (c) => {
    const server = c.req.param("server");
    // Extract the full key (username/uuid-filename) from the wildcard path
    const rawKey = c.req.path.split(`/d/${server}/`)[1]; 
    if (!rawKey) return c.text("Invalid Key", 400);

    const client = server === "1" ? s3Server1 : s3Server2;
    const bucket = server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");

    try {
        const command = new GetObjectCommand({
            Bucket: bucket,
            Key: rawKey,
            ResponseContentDisposition: 'attachment' // Force download
        });
        // Generate Link valid for 1 hour
        const url = await getSignedUrl(client, command, { expiresIn: 3600 });
        
        // REDIRECT USER TO R2
        return c.redirect(url);
    } catch (e) {
        return c.text("File Not Found or Error", 404);
    }
});

// =======================
// 7. CRON & CLEANUP
// =======================
app.post("/delete/:id", async (c) => {
    const cookie = getCookie(c, "auth"); const user = await getUser(cookie || ""); if(!user) return c.redirect("/login");
    const id = c.req.param("id"); const fileRes = await kv.get<FileData>(["files", user.username, id]);
    if (fileRes.value) { 
        await deleteFileFromR2(fileRes.value); 
        await kv.atomic()
            .delete(["files", user.username, id])
            .set(["users", user.username], { ...user, usedStorage: Math.max(0, user.usedStorage - fileRes.value.sizeBytes) })
            .commit();
    }
    return c.redirect("/");
});

async function deleteFileFromR2(f: FileData) {
    const bucket = Deno.env.get(`R2_${f.server}_BUCKET_NAME`);
    const client = f.server === "1" ? s3Server1 : s3Server2;
    try { await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: f.r2Key })); } catch (e) {}
}

// =======================
// 8. AUTHENTICATION
// =======================
app.get("/login", (c) => c.html(<Layout title="Login"><div class="max-w-sm mx-auto mt-24 glass p-8 rounded-2xl border border-zinc-700"><h1 class="text-3xl font-black mb-2 text-center text-yellow-500 italic">GOLD STORAGE</h1><p class="text-center text-zinc-500 text-xs mb-8">လုံခြုံစိတ်ချရသော Cloud Storage</p><form action="/login" method="post" class="space-y-4"><input name="username" placeholder="အမည် (Username)" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white focus:border-yellow-500 outline-none" /><input type="password" name="password" placeholder="စကားဝှက် (Password)" required class="w-full bg-zinc-900 border border-zinc-700 p-3 rounded-xl text-white focus:border-yellow-500 outline-none" /><button class="w-full bg-gradient-to-r from-yellow-600 to-yellow-500 text-black font-bold py-3 rounded-xl hover:brightness-110">ဝင်မည်</button></form><p class="text-center text-xs mt-6 text-zinc-500">အကောင့်မရှိဘူးလား? <a href="/register" class="text-yellow-500 font-bold hover:underline">အကောင့်သစ်ဖွင့်မယ်</a></p></div></Layout>));
app.post("/login", async (c) => { 
    const { username, password } = await c.req.parseBody(); 
    const u = String(username).trim(); 
    const user = await getUser(u); 
    if (user && user.passwordHash === await hashPassword(String(password).trim())) { 
        setCookie(c, "auth", u, { path: "/", httpOnly: true, secure: true, sameSite: "Strict", maxAge: 86400 * 30 }); 
        return c.redirect("/"); 
    } 
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

// =======================
// 9. SERVER
// =======================
Deno.serve(app.fetch);
