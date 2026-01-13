/** @jsxImportSource npm:hono@4/jsx */
import { Hono } from "npm:hono@4";
import { getCookie, setCookie, deleteCookie } from "npm:hono@4/cookie";
import { S3Client, PutObjectCommand, DeleteObjectCommand } from "npm:@aws-sdk/client-s3";

const app = new Hono();
const kv = await Deno.openKv();

// =======================
// 1. CONFIG & R2 CLIENTS
// =======================
const ADMIN_USERNAME = "admin"; // 🔥 Admin ဝင်မည့် Username
const SALT = "my-secret-salt";  // Password Hash ဖို့

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
    plan: "Free" | "VIP 1 Month" | "VIP 1 Year" | "Lifetime"; 
    storageLimit: number; // in Bytes
    usedStorage: number;
    createdAt: number;
    expiryDate?: number; // Plan Expiry
}

interface FileData { 
    id: string; 
    name: string; 
    originalName: string;
    size: string; 
    sizeBytes: number;
    server: "1" | "2"; 
    r2Key: string;
    downloadUrl: string; 
    uploadedAt: number;
    expiresAt?: number; // 0 = Lifetime
    type: "image" | "video" | "other";
}

// Password Hash Function
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

// =======================
// 3. UI LAYOUT & SCRIPTS
// =======================
const mainScript = `
<script>
    function switchTab(tab) {
        document.querySelectorAll('.file-item').forEach(el => el.classList.add('hidden'));
        document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('text-yellow-500', 'border-yellow-500'));
        
        document.getElementById('btn-' + tab).classList.add('text-yellow-500', 'border-yellow-500');
        
        if(tab === 'all') {
            document.querySelectorAll('.file-item').forEach(el => el.classList.remove('hidden'));
        } else {
            document.querySelectorAll('.type-' + tab).forEach(el => el.classList.remove('hidden'));
        }
    }

    function uploadFile(event) {
        event.preventDefault();
        const form = document.getElementById('uploadForm');
        const fileInput = document.getElementById('fileInput');
        
        if(fileInput.files.length === 0) { alert("ဖိုင်ရွေးပါ"); return; }

        const formData = new FormData(form);
        const xhr = new XMLHttpRequest();
        
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const progressContainer = document.getElementById('progressContainer');
        const submitBtn = document.getElementById('submitBtn');

        progressContainer.classList.remove('hidden');
        submitBtn.disabled = true;
        submitBtn.innerText = "Upload နေသည်...";

        xhr.upload.addEventListener("progress", (e) => {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = percent + "%";
                progressText.innerText = percent + "%";
            }
        });

        xhr.onload = () => {
            if (xhr.status === 200) {
                progressBar.classList.add('bg-green-500');
                submitBtn.innerText = "ပြီးပါပြီ!";
                window.location.reload();
            } else {
                alert("Error: " + xhr.responseText);
                submitBtn.disabled = false;
                submitBtn.innerText = "Upload";
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
            <style>{`body { font-family: 'Padauk', sans-serif; }`}</style>
        </head>
        <body class="bg-slate-900 text-white min-h-screen">
            <nav class="bg-slate-800 p-4 border-b border-slate-700 flex justify-between items-center sticky top-0 z-50 shadow-lg">
                <a href="/" class="text-xl font-black text-yellow-500 italic flex items-center gap-2">
                    <i class="fa-solid fa-hard-drive"></i> GOLD STORAGE
                </a>
                {props.user ? (
                    <div class="flex gap-3 items-center">
                        <span class="text-xs font-bold text-gray-400 hidden sm:inline">{props.user.username}</span>
                        <span class="bg-yellow-500 text-black px-2 py-0.5 rounded uppercase text-[10px] font-bold">{props.user.plan}</span>
                        {props.user.username === ADMIN_USERNAME && <a href="/admin" class="text-xs bg-purple-600 px-3 py-1.5 rounded font-bold">Admin</a>}
                        <a href="/logout" class="text-xs bg-red-600 px-3 py-1.5 rounded font-bold">LogOut</a>
                    </div>
                ) : (
                    <a href="/login" class="text-xs bg-blue-600 px-3 py-1.5 rounded hover:bg-blue-500 font-bold">Login</a>
                )}
            </nav>
            <main class="p-4 max-w-4xl mx-auto pb-20">{props.children}</main>
            <div dangerouslySetInnerHTML={{__html: mainScript}} />
        </body>
    </html>
);

// =======================
// 4. MAIN ROUTES
// =======================

// 🔥 DASHBOARD
app.get("/", async (c) => {
    const cookie = getCookie(c, "auth");
    if(!cookie) return c.redirect("/login");
    const user = await getUser(cookie);
    if(!user) return c.redirect("/login");

    // Fetch Files
    const iter = kv.list<FileData>({ prefix: ["files", user.username] }, { reverse: true });
    const files = [];
    let totalBytes = 0;

    for await (const res of iter) {
        files.push(res.value);
        totalBytes += res.value.sizeBytes;
    }

    // Storage Calculation
    const totalMB = (totalBytes / 1024 / 1024).toFixed(2);
    const limitMB = (user.storageLimit / 1024 / 1024).toFixed(0);
    const usedPercent = Math.min(100, (totalBytes / user.storageLimit) * 100);

    return c.html(
        <Layout user={user}>
            
            {/* STORAGE STATUS */}
            <div class="bg-slate-800 p-4 rounded-xl border border-slate-700 mb-6 flex items-center justify-between">
                <div>
                    <p class="text-xs text-gray-400 uppercase font-bold">Storage Plan: <span class="text-yellow-500">{user.plan}</span></p>
                    <p class="text-lg font-black">{totalMB} MB <span class="text-gray-500 text-sm font-normal">/ {user.storageLimit > 100 * 1024*1024*1024 ? "Unlimited" : limitMB + " MB"}</span></p>
                </div>
                <div class="w-24 h-24 relative flex items-center justify-center">
                    <div class="absolute inset-0 rounded-full border-4 border-slate-700"></div>
                    <div class="absolute inset-0 rounded-full border-4 border-blue-500" style={`clip-path: inset(${100 - usedPercent}% 0 0 0)`}></div>
                    <span class="text-xs font-bold">{usedPercent.toFixed(0)}%</span>
                </div>
            </div>

            {/* UPLOAD FORM */}
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg mb-8">
                <h2 class="font-bold text-lg mb-4 flex items-center gap-2 text-blue-400">
                    <i class="fa-solid fa-cloud-arrow-up"></i> Upload New File
                </h2>
                
                <form id="uploadForm" onsubmit="uploadFile(event)" class="space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="label-text">Rename (Optional)</label>
                            <input name="customName" placeholder="ဖိုင်နာမည်အသစ်ပေးမည်..." class="input-box w-full bg-slate-900 border border-slate-600 rounded p-2 text-sm" />
                        </div>
                        <div>
                            <label class="label-text">Delete After (Expiry)</label>
                            <select name="expiry" class="input-box w-full bg-slate-900 border border-slate-600 rounded p-2 text-sm">
                                <option value="0">Lifetime (မဖျက်ပါ)</option>
                                <option value="7">1 Week</option>
                                <option value="30">1 Month</option>
                            </select>
                        </div>
                    </div>

                    <div>
                        <label class="label-text mb-2 block">Choose Server</label>
                        <div class="grid grid-cols-2 gap-4">
                            <label class="cursor-pointer">
                                <input type="radio" name="server" value="1" class="peer sr-only" checked />
                                <div class="p-3 bg-slate-900 border border-slate-600 rounded peer-checked:border-blue-500 peer-checked:bg-blue-900/30 text-center text-sm font-bold">Server 1</div>
                            </label>
                            <label class="cursor-pointer">
                                <input type="radio" name="server" value="2" class="peer sr-only" />
                                <div class="p-3 bg-slate-900 border border-slate-600 rounded peer-checked:border-yellow-500 peer-checked:bg-yellow-900/30 text-center text-sm font-bold">Server 2</div>
                            </label>
                        </div>
                    </div>

                    <div class="border-2 border-dashed border-slate-600 rounded-xl p-6 text-center hover:border-blue-500 transition bg-slate-900/50">
                        <input type="file" id="fileInput" name="file" class="w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:bg-blue-600 file:text-white cursor-pointer"/>
                    </div>

                    <div id="progressContainer" class="hidden">
                        <div class="flex justify-between text-xs mb-1"><span>Uploading...</span><span id="progressText">0%</span></div>
                        <div class="w-full bg-slate-700 rounded-full h-2"><div id="progressBar" class="bg-blue-600 h-2 rounded-full" style="width: 0%"></div></div>
                    </div>

                    <button id="submitBtn" class="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-bold transition">Upload File</button>
                </form>
            </div>

            {/* FILE MANAGER TABS */}
            <div class="flex gap-4 border-b border-slate-700 mb-4 pb-2">
                <button id="btn-all" onclick="switchTab('all')" class="tab-btn text-sm font-bold text-yellow-500 border-b-2 border-yellow-500 pb-1">All Files</button>
                <button id="btn-video" onclick="switchTab('video')" class="tab-btn text-sm font-bold text-gray-400 pb-1 hover:text-white">Videos</button>
                <button id="btn-image" onclick="switchTab('image')" class="tab-btn text-sm font-bold text-gray-400 pb-1 hover:text-white">Images</button>
                <button id="btn-other" onclick="switchTab('other')" class="tab-btn text-sm font-bold text-gray-400 pb-1 hover:text-white">Others</button>
            </div>

            {/* FILE LIST */}
            <div class="space-y-3">
                {files.map(f => (
                    <div class={`file-item type-${f.type} bg-slate-800 p-4 rounded-lg border border-slate-700 flex justify-between items-center group`}>
                        <div class="flex items-center gap-4 overflow-hidden">
                            <div class={`w-10 h-10 rounded flex items-center justify-center text-xl ${f.type === 'image' ? 'text-yellow-400 bg-yellow-900/20' : f.type === 'video' ? 'text-blue-400 bg-blue-900/20' : 'text-gray-400 bg-gray-800'}`}>
                                <i class={`fa-solid ${f.type === 'image' ? 'fa-image' : f.type === 'video' ? 'fa-video' : 'fa-file'}`}></i>
                            </div>
                            <div class="min-w-0">
                                <p class="font-bold text-sm truncate text-white">{f.name}</p>
                                <div class="flex gap-3 text-[10px] text-gray-400">
                                    <span>{f.size}</span>
                                    <span>{new Date(f.uploadedAt).toLocaleDateString()}</span>
                                    {f.expiresAt && <span class="text-red-400">Expires: {new Date(f.expiresAt).toLocaleDateString()}</span>}
                                </div>
                            </div>
                        </div>
                        <div class="flex gap-2">
                            <a href={f.downloadUrl} target="_blank" class="p-2 bg-slate-700 rounded hover:bg-blue-600 text-white"><i class="fa-solid fa-download"></i></a>
                            <button onclick={`navigator.clipboard.writeText('${f.downloadUrl}'); alert('Copied')`} class="p-2 bg-slate-700 rounded hover:bg-green-600 text-white"><i class="fa-regular fa-copy"></i></button>
                            <form action={`/delete/${f.id}`} method="post" onsubmit="return confirm('ဖျက်မှာသေချာလား?')">
                                <button class="p-2 bg-slate-700 rounded hover:bg-red-600 text-white"><i class="fa-solid fa-trash"></i></button>
                            </form>
                        </div>
                    </div>
                ))}
                {files.length === 0 && <p class="text-center text-gray-500 py-10">No files found.</p>}
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

    const body = await c.req.parseBody();
    const file = body['file'];
    const serverChoice = String(body['server']);
    const customName = String(body['customName']).trim();
    const expiryDays = parseInt(String(body['expiry']));

    if (file instanceof File) {
        // Check Storage Limit
        if (user.usedStorage + file.size > user.storageLimit) {
            return c.text("Storage Limit Reached! Upgrade Plan.", 400);
        }

        try {
            // Rename Logic
            let finalName = file.name;
            if (customName) {
                const ext = file.name.split('.').pop();
                finalName = customName.endsWith('.' + ext) ? customName : customName + '.' + ext;
            }
            const safeName = finalName.replace(/[^a-zA-Z0-9.-]/g, "_");
            const r2Key = `${user.username}/${crypto.randomUUID()}-${safeName}`;

            // Category Logic
            let type: "image" | "video" | "other" = "other";
            if (file.type.startsWith("image/")) type = "image";
            else if (file.type.startsWith("video/")) type = "video";

            const client = serverChoice === "1" ? s3Server1 : s3Server2;
            const bucket = serverChoice === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");

            await client.send(new PutObjectCommand({
                Bucket: bucket,
                Key: r2Key,
                Body: new Uint8Array(await file.arrayBuffer()),
                ContentType: file.type,
            }));

            const finalUrl = serverChoice === "1" ? `${DOMAIN_1}${r2Key}` : `${DOMAIN_2}${r2Key}`;
            
            const fileData: FileData = {
                id: crypto.randomUUID(),
                name: finalName,
                originalName: file.name,
                size: (file.size / 1024 / 1024).toFixed(2) + " MB",
                sizeBytes: file.size,
                server: serverChoice as "1" | "2",
                r2Key: r2Key,
                downloadUrl: finalUrl,
                uploadedAt: Date.now(),
                type: type,
                expiresAt: expiryDays > 0 ? Date.now() + (expiryDays * 86400000) : 0
            };

            await kv.set(["files", user.username, fileData.id], fileData);
            
            // Update User Storage
            user.usedStorage += file.size;
            await kv.set(["users", user.username], user);

            return c.text("Success");
        } catch (e: any) {
            return c.text("Upload Failed: " + e.message, 500);
        }
    }
    return c.text("No file", 400);
});

// 🔥 DELETE HANDLER
app.post("/delete/:id", async (c) => {
    const cookie = getCookie(c, "auth");
    const user = await getUser(cookie || "");
    if(!user) return c.redirect("/login");

    const id = c.req.param("id");
    const fileRes = await kv.get<FileData>(["files", user.username, id]);
    
    if (fileRes.value) {
        const f = fileRes.value;
        const client = f.server === "1" ? s3Server1 : s3Server2;
        const bucket = f.server === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");

        // Delete from R2
        try {
            await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: f.r2Key }));
        } catch (e) { console.error("R2 Delete Error", e); }

        // Delete from DB & Update Storage
        await kv.delete(["files", user.username, id]);
        user.usedStorage = Math.max(0, user.usedStorage - f.sizeBytes);
        await kv.set(["users", user.username], user);
    }

    return c.redirect("/");
});

// =======================
// 5. AUTH SYSTEM (Password Added)
// =======================
app.get("/login", (c) => c.html(
    <Layout title="Login">
        <div class="max-w-sm mx-auto mt-20 bg-slate-800 p-8 rounded-xl border border-slate-700 shadow-2xl">
            <h1 class="text-2xl font-black mb-6 text-center text-yellow-500 italic">GOLD STORAGE</h1>
            <form action="/login" method="post" class="space-y-4">
                <input name="username" placeholder="Username" required class="input-box w-full p-3 bg-slate-900 border border-slate-600 rounded text-white" />
                <input type="password" name="password" placeholder="Password" required class="input-box w-full p-3 bg-slate-900 border border-slate-600 rounded text-white" />
                <button class="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded font-bold">Login</button>
            </form>
            <p class="text-center text-xs mt-4 text-gray-400">အကောင့်မရှိဘူးလား? <a href="/register" class="text-blue-400 font-bold">အကောင့်သစ်ဖွင့်မယ်</a></p>
        </div>
    </Layout>
));

app.post("/login", async (c) => {
    const { username, password } = await c.req.parseBody();
    const u = String(username).trim();
    const p = String(password).trim();
    const user = await getUser(u);

    if (user && user.passwordHash === await hashPassword(p)) {
        setCookie(c, "auth", u, { path: "/", maxAge: 86400 * 30 });
        return c.redirect("/");
    }
    return c.html(<Layout><p class="text-center text-red-500 mt-20">Username သို့မဟုတ် Password မှားယွင်းနေပါသည်။ <a href="/login" class="underline">ပြန်ကြိုးစားပါ</a></p></Layout>);
});

app.get("/register", (c) => c.html(
    <Layout title="Register">
        <div class="max-w-sm mx-auto mt-20 bg-slate-800 p-8 rounded-xl border border-slate-700">
            <h1 class="text-xl font-bold mb-6 text-center text-white">အကောင့်သစ်ဖွင့်မည်</h1>
            <form action="/register" method="post" class="space-y-4">
                <input name="username" placeholder="Username" required class="w-full p-3 bg-slate-900 border border-slate-600 rounded text-white" />
                <input type="password" name="password" placeholder="Password" required class="w-full p-3 bg-slate-900 border border-slate-600 rounded text-white" />
                <button class="w-full bg-green-600 hover:bg-green-500 py-3 rounded font-bold">Register</button>
            </form>
        </div>
    </Layout>
));

app.post("/register", async (c) => {
    const { username, password } = await c.req.parseBody();
    const u = String(username).trim();
    const p = String(password).trim();

    if (await getUser(u)) return c.html(<Layout><p class="text-center text-red-500 mt-20">Username ရှိပြီးသားဖြစ်နေသည်။</p></Layout>);

    const newUser: User = {
        username: u,
        passwordHash: await hashPassword(p),
        plan: "Free",
        storageLimit: 200 * 1024 * 1024, // 200MB Default Free
        usedStorage: 0,
        createdAt: Date.now()
    };
    await kv.set(["users", u], newUser);
    return c.redirect("/login");
});

app.get("/logout", (c) => { deleteCookie(c, "auth"); return c.redirect("/login"); });

// =======================
// 6. ADMIN PANEL
// =======================
app.get("/admin", async (c) => {
    const cookie = getCookie(c, "auth");
    if(cookie !== ADMIN_USERNAME) return c.redirect("/");
    
    // List All Users
    const iter = kv.list<User>({ prefix: ["users"] });
    const users = [];
    for await (const res of iter) users.push(res.value);

    return c.html(
        <Layout title="Admin Panel" user={{ username: ADMIN_USERNAME, plan: "Lifetime", role: "admin" } as any}>
            <h1 class="text-2xl font-bold mb-6">User Management</h1>
            <div class="space-y-4">
                {users.map(u => (
                    <div class="bg-slate-800 p-4 rounded border border-slate-700 flex justify-between items-center">
                        <div>
                            <p class="font-bold">{u.username}</p>
                            <p class="text-xs text-gray-400">Plan: {u.plan} | Used: {(u.usedStorage/1024/1024).toFixed(2)} MB</p>
                        </div>
                        <form action="/admin/upgrade" method="post" class="flex gap-2">
                            <input type="hidden" name="username" value={u.username} />
                            <select name="plan" class="bg-slate-900 text-xs p-2 rounded">
                                <option value="Free">Free (200MB)</option>
                                <option value="VIP 1 Month">VIP 1 Month (10GB)</option>
                                <option value="VIP 1 Year">VIP 1 Year (100GB)</option>
                                <option value="Lifetime">Lifetime (Unlimited)</option>
                            </select>
                            <button class="bg-blue-600 px-3 py-1 rounded text-xs font-bold">Update</button>
                        </form>
                    </div>
                ))}
            </div>
        </Layout>
    );
});

app.post("/admin/upgrade", async (c) => {
    const cookie = getCookie(c, "auth");
    if(cookie !== ADMIN_USERNAME) return c.text("Unauthorized", 403);
    
    const { username, plan } = await c.req.parseBody();
    const user = await getUser(String(username));
    
    if(user) {
        user.plan = String(plan) as any;
        if(plan === "Free") user.storageLimit = 200 * 1024 * 1024; // 200MB
        else if(plan === "VIP 1 Month") user.storageLimit = 10 * 1024 * 1024 * 1024; // 10GB
        else if(plan === "VIP 1 Year") user.storageLimit = 100 * 1024 * 1024 * 1024; // 100GB
        else if(plan === "Lifetime") user.storageLimit = 1000 * 1024 * 1024 * 1024 * 1024; // 1TB (Unlimited-ish)
        
        await kv.set(["users", user.username], user);
    }
    return c.redirect("/admin");
});

Deno.serve(app.fetch);
