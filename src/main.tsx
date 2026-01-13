/** @jsxImportSource npm:hono@4/jsx */
import { Hono } from "npm:hono@4";
import { getCookie, setCookie, deleteCookie } from "npm:hono@4/cookie";
import { S3Client, PutObjectCommand } from "npm:@aws-sdk/client-s3";

const app = new Hono();
const kv = await Deno.openKv();

// =======================
// 1. R2 CLIENTS SETUP
// =======================

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

const DOMAIN_1 = "https://abc-iqowoq-clouding.vercel.app/api/1/";
const DOMAIN_2 = "https://lugyicloud.vercel.app/api/12/";

// =======================
// 2. HELPER FUNCTIONS
// =======================
interface User { username: string; passwordHash: string; role: "free" | "vip"; }
interface FileData { 
    id: string; 
    name: string; 
    size: string; 
    server: "1" | "2"; 
    downloadUrl: string; 
    uploadedAt: number; 
}

async function getUser(username: string) { const res = await kv.get<User>(["users", username]); return res.value; }

// 🔥 JAVASCRIPT FOR PROGRESS BAR
const uploadScript = `
<script>
    function uploadFile(event) {
        event.preventDefault();
        const form = document.getElementById('uploadForm');
        const fileInput = document.getElementById('fileInput');
        
        if(fileInput.files.length === 0) {
            alert("ကျေးဇူးပြု၍ ဖိုင်ရွေးချယ်ပါ");
            return;
        }

        const formData = new FormData(form);
        const xhr = new XMLHttpRequest();
        
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const progressContainer = document.getElementById('progressContainer');
        const submitBtn = document.getElementById('submitBtn');

        // UI ပြောင်းလဲခြင်း
        progressContainer.classList.remove('hidden');
        submitBtn.disabled = true;
        submitBtn.classList.add('opacity-50', 'cursor-not-allowed');
        submitBtn.innerText = "တင်နေပါသည်...";

        // Progress တွက်ချက်ခြင်း
        xhr.upload.addEventListener("progress", (e) => {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = percent + "%";
                progressText.innerText = percent + "%";
            }
        });

        // ပြီးဆုံးသွားသောအခါ
        xhr.onload = () => {
            if (xhr.status === 200) {
                // Success
                progressBar.classList.remove('bg-blue-600');
                progressBar.classList.add('bg-green-500');
                submitBtn.innerText = "အောင်မြင်ပါသည်!";
                setTimeout(() => window.location.reload(), 1000);
            } else {
                alert("Upload Failed: " + xhr.responseText);
                submitBtn.disabled = false;
                submitBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                submitBtn.innerText = "စတင် တင်မည်";
                progressContainer.classList.add('hidden');
            }
        };

        xhr.onerror = () => {
            alert("Connection Error!");
            submitBtn.disabled = false;
            submitBtn.innerText = "စတင် တင်မည်";
        };

        xhr.open("POST", "/upload");
        xhr.send(formData);
    }
</script>
`;

const Layout = (props: { children: any; title?: string; user?: User | null }) => (
    <html>
        <head>
            <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>{props.title || "Gold Storage"}</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" />
            {/* Font for Myanmar Text (Optional but good for some devices) */}
            <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap" rel="stylesheet" />
            <style>{`body { font-family: 'Padauk', sans-serif; }`}</style>
        </head>
        <body class="bg-slate-900 text-white min-h-screen">
            <nav class="bg-slate-800 p-4 border-b border-slate-700 flex justify-between items-center sticky top-0 z-50 shadow-lg">
                <a href="/" class="text-xl font-black text-yellow-500 italic flex items-center gap-2">
                    <i class="fa-solid fa-cloud"></i> GOLD STORAGE
                </a>
                {props.user ? (
                    <div class="flex gap-3 items-center">
                        <span class="text-xs font-bold text-gray-400 hidden sm:inline">မင်္ဂလာပါ, {props.user.username}</span>
                        <span class="bg-yellow-500 text-black px-2 py-0.5 rounded uppercase text-[10px] font-bold">{props.user.role === 'vip' ? 'VIP' : 'FREE'}</span>
                        <a href="/logout" class="text-xs bg-red-600 px-3 py-1.5 rounded hover:bg-red-500 transition font-bold">ထွက်မည်</a>
                    </div>
                ) : (
                    <a href="/login" class="text-xs bg-blue-600 px-3 py-1.5 rounded hover:bg-blue-500 font-bold">ဝင်မည်</a>
                )}
            </nav>
            <main class="p-4 max-w-3xl mx-auto pb-20">{props.children}</main>
            <div dangerouslySetInnerHTML={{__html: uploadScript}} />
        </body>
    </html>
);

// =======================
// 3. ROUTES
// =======================

// 🔥 HOME / DASHBOARD
app.get("/", async (c) => {
    const cookie = getCookie(c, "auth");
    if(!cookie) return c.redirect("/login");
    
    const user = await getUser(cookie);
    if(!user) return c.redirect("/login");

    const iter = kv.list<FileData>({ prefix: ["files", user.username] }, { reverse: true });
    const files = [];
    for await (const res of iter) files.push(res.value);

    return c.html(
        <Layout user={user}>
            {/* UPLOAD BOX */}
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg mb-8">
                <h2 class="font-bold text-lg mb-4 flex items-center gap-2 text-blue-400">
                    <i class="fa-solid fa-cloud-arrow-up"></i> ဖိုင်အသစ် တင်ရန်
                </h2>
                
                <form id="uploadForm" onsubmit="uploadFile(event)" class="space-y-4">
                    
                    {/* Server Selection */}
                    <div>
                        <label class="text-xs font-bold text-gray-400 uppercase mb-2 block">ဆာဗာ ရွေးချယ်ပါ</label>
                        <div class="grid grid-cols-2 gap-4">
                            <label class="cursor-pointer relative group">
                                <input type="radio" name="server" value="1" class="peer sr-only" checked />
                                <div class="p-3 bg-slate-900 border border-slate-700 rounded-lg peer-checked:border-blue-500 peer-checked:bg-blue-500/10 text-center transition hover:bg-slate-700 group-active:scale-95">
                                    <span class="font-bold text-sm block text-white">Server 1</span>
                                    <span class="text-[10px] text-gray-500">abc-iqowoq</span>
                                </div>
                                <div class="absolute top-2 right-2 text-blue-500 opacity-0 peer-checked:opacity-100"><i class="fa-solid fa-circle-check"></i></div>
                            </label>
                            <label class="cursor-pointer relative group">
                                <input type="radio" name="server" value="2" class="peer sr-only" />
                                <div class="p-3 bg-slate-900 border border-slate-700 rounded-lg peer-checked:border-yellow-500 peer-checked:bg-yellow-500/10 text-center transition hover:bg-slate-700 group-active:scale-95">
                                    <span class="font-bold text-sm block text-white">Server 2</span>
                                    <span class="text-[10px] text-gray-500">lugyicloud</span>
                                </div>
                                <div class="absolute top-2 right-2 text-yellow-500 opacity-0 peer-checked:opacity-100"><i class="fa-solid fa-circle-check"></i></div>
                            </label>
                        </div>
                    </div>

                    {/* File Input */}
                    <div class="border-2 border-dashed border-slate-600 rounded-xl p-6 text-center hover:border-blue-500 transition bg-slate-900/50 group">
                        <input type="file" id="fileInput" name="file" class="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-xs file:font-bold file:bg-blue-600 file:text-white hover:file:bg-blue-700 cursor-pointer"/>
                        <p class="text-[10px] text-gray-500 mt-2 group-hover:text-blue-400 transition">
                            <i class="fa-solid fa-circle-info"></i> အများဆုံး ပမာဏ: 20MB (Free) | 1GB (VIP)
                        </p>
                    </div>

                    {/* 🔥 PROGRESS BAR AREA */}
                    <div id="progressContainer" class="hidden">
                        <div class="flex justify-between text-xs text-gray-300 mb-1 font-bold">
                            <span>Uploading...</span>
                            <span id="progressText">0%</span>
                        </div>
                        <div class="w-full bg-slate-700 rounded-full h-2.5 overflow-hidden">
                            <div id="progressBar" class="bg-blue-600 h-2.5 rounded-full transition-all duration-300" style="width: 0%"></div>
                        </div>
                    </div>

                    <button id="submitBtn" class="w-full bg-gradient-to-r from-blue-600 to-cyan-500 py-3 rounded-xl font-bold shadow-lg hover:brightness-110 transition active:scale-95">
                        စတင် တင်မည်
                    </button>
                </form>
            </div>

            {/* FILE LIST */}
            <h3 class="font-bold text-gray-400 mb-4 text-sm uppercase flex items-center gap-2">
                <i class="fa-solid fa-folder-open"></i> မိမိဖိုင်များ ({files.length})
            </h3>
            <div class="space-y-3">
                {files.map(f => (
                    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 flex justify-between items-center group hover:border-slate-500 transition shadow-md">
                        <div class="flex items-center gap-4 overflow-hidden">
                            <div class={`w-12 h-12 rounded-lg flex items-center justify-center text-xl flex-shrink-0 ${f.server === '1' ? 'bg-blue-500/10 text-blue-400' : 'bg-yellow-500/10 text-yellow-400'}`}>
                                <i class={`fa-solid ${f.name.match(/\.(jpg|png|jpeg|gif)$/i) ? 'fa-image' : (f.name.match(/\.(mp4|mkv|mov)$/i) ? 'fa-file-video' : 'fa-file')}`}></i>
                            </div>
                            <div class="min-w-0">
                                <p class="font-bold text-sm truncate text-white mb-1">{f.name}</p>
                                <div class="flex items-center gap-2 text-[10px] text-gray-400 font-mono">
                                    <span class="bg-slate-900 px-1.5 py-0.5 rounded border border-slate-700">SRV-{f.server}</span>
                                    <span>{f.size}</span>
                                    <span>{new Date(f.uploadedAt).toLocaleDateString()}</span>
                                </div>
                            </div>
                        </div>
                        <div class="flex gap-2">
                            <a href={f.downloadUrl} target="_blank" class="w-8 h-8 flex items-center justify-center bg-slate-700 hover:bg-blue-600 text-white rounded-lg transition" title="Download">
                                <i class="fa-solid fa-download"></i>
                            </a>
                            <button onclick={`navigator.clipboard.writeText('${f.downloadUrl}'); this.innerHTML='<i class="fa-solid fa-check"></i>'; setTimeout(()=>this.innerHTML='<i class="fa-regular fa-copy"></i>', 1500)`} class="w-8 h-8 flex items-center justify-center bg-slate-700 hover:bg-green-600 text-white rounded-lg transition" title="Copy Link">
                                <i class="fa-regular fa-copy"></i>
                            </button>
                        </div>
                    </div>
                ))}
                {files.length === 0 && (
                    <div class="text-center text-gray-500 py-12 bg-slate-800/50 rounded-xl border border-dashed border-slate-700">
                        <i class="fa-solid fa-box-open text-4xl mb-3 opacity-50"></i>
                        <p>ဖိုင်များ မရှိသေးပါ။</p>
                    </div>
                )}
            </div>
        </Layout>
    );
});

// 🔥 UPLOAD HANDLER
app.post("/upload", async (c) => {
    const cookie = getCookie(c, "auth");
    if(!cookie) return c.text("Unauthorized", 401);
    const user = await getUser(cookie);
    if(!user) return c.text("User not found", 401);

    const body = await c.req.parseBody();
    const file = body['file'];
    const serverChoice = String(body['server']);

    if (file instanceof File) {
        if (file.size > 20 * 1024 * 1024) {
             return c.text("Error: ဖိုင်ဆိုဒ် ကြီးလွန်းပါသည် (Max 20MB)", 400);
        }

        try {
            const safeName = file.name.replace(/[^a-zA-Z0-9.-]/g, "_"); 
            const objectKey = `${crypto.randomUUID()}-${safeName}`;
            
            const client = serverChoice === "1" ? s3Server1 : s3Server2;
            const bucket = serverChoice === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");

            const buffer = await file.arrayBuffer();
            await client.send(new PutObjectCommand({
                Bucket: bucket,
                Key: objectKey,
                Body: new Uint8Array(buffer),
                ContentType: file.type,
            }));

            let finalUrl = "";
            if (serverChoice === "1") {
                finalUrl = `${DOMAIN_1}${objectKey}`;
            } else {
                finalUrl = `${DOMAIN_2}${objectKey}`;
            }

            const fileData: FileData = {
                id: crypto.randomUUID(),
                name: file.name,
                size: (file.size / 1024 / 1024).toFixed(2) + " MB",
                server: serverChoice as "1" | "2",
                downloadUrl: finalUrl,
                uploadedAt: Date.now()
            };

            await kv.set(["files", user.username, fileData.id], fileData);

            return c.text("Success");

        } catch (e: any) {
            return c.text("Upload Failed: " + e.message, 500);
        }
    }
    return c.text("No file selected", 400);
});

// 🔥 LOGIN PAGE (BURMESE)
app.get("/login", (c) => c.html(
    <Layout title="Login">
        <div class="max-w-sm mx-auto mt-20 bg-slate-800 p-8 rounded-xl border border-slate-700 shadow-2xl">
            <h1 class="text-2xl font-black mb-2 text-center text-yellow-500 italic">GOLD STORAGE</h1>
            <p class="text-gray-400 text-xs text-center mb-6">ဖိုင်သိမ်းဆည်းရန် အကောင့်ဝင်ပါ</p>
            <form action="/login" method="post" class="space-y-4">
                <div>
                    <label class="text-[10px] uppercase font-bold text-gray-500">အသုံးပြုသူ အမည် (Username)</label>
                    <input name="username" placeholder="Username..." required class="w-full p-3 bg-slate-900 border border-slate-700 rounded-lg text-white mt-1 focus:border-blue-500 outline-none transition" />
                </div>
                <button class="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-lg font-bold text-sm shadow-lg transition active:scale-95">
                    အကောင့်ဝင်မည် / အကောင့်သစ်ဖွင့်မည်
                </button>
            </form>
        </div>
    </Layout>
));

app.post("/login", async (c) => {
    const { username } = await c.req.parseBody();
    const u = String(username).trim();
    if(!u) return c.redirect("/login");
    
    const existing = await getUser(u);
    if (!existing) {
        await kv.set(["users", u], { username: u, passwordHash: "demo", role: "free" });
    }
    
    setCookie(c, "auth", u, { path: "/", maxAge: 86400 * 30 });
    return c.redirect("/");
});

app.get("/logout", (c) => { deleteCookie(c, "auth"); return c.redirect("/login"); });

Deno.serve(app.fetch);
