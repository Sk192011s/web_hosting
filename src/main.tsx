/** @jsxImportSource npm:hono@4/jsx */ 
import { Hono } from "npm:hono@4";
import { getCookie, setCookie, deleteCookie } from "npm:hono@4/cookie";
import { S3Client, PutObjectCommand } from "npm:@aws-sdk/client-s3";

const app = new Hono();
const kv = await Deno.openKv();

// =======================
// 1. R2 CLIENTS SETUP
// =======================

// Server 1 Client
const s3Server1 = new S3Client({
  region: "auto",
  endpoint: `https://${Deno.env.get("R2_1_ACCOUNT_ID")}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: Deno.env.get("R2_1_ACCESS_KEY_ID")!,
    secretAccessKey: Deno.env.get("R2_1_SECRET_ACCESS_KEY")!,
  },
});

// Server 2 Client
const s3Server2 = new S3Client({
  region: "auto",
  endpoint: `https://${Deno.env.get("R2_2_ACCOUNT_ID")}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: Deno.env.get("R2_2_ACCESS_KEY_ID")!,
    secretAccessKey: Deno.env.get("R2_2_SECRET_ACCESS_KEY")!,
  },
});

// Vercel Domains (Link ပြန်ထုတ်ပေးရန်)
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

const Layout = (props: { children: any; title?: string; user?: User | null }) => (
    <html>
        <head>
            <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>{props.title || "Gold Storage"}</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" />
        </head>
        <body class="bg-slate-900 text-white min-h-screen">
            <nav class="bg-slate-800 p-4 border-b border-slate-700 flex justify-between items-center sticky top-0 z-50">
                <a href="/" class="text-xl font-black text-yellow-500 italic">GOLD STORAGE</a>
                {props.user ? (
                    <div class="flex gap-3 items-center">
                        <span class="text-xs font-bold text-gray-400">{props.user.username} <span class="bg-yellow-500 text-black px-1 rounded ml-1 uppercase text-[10px]">{props.user.role}</span></span>
                        <a href="/logout" class="text-xs bg-red-600 px-3 py-1.5 rounded hover:bg-red-500">Logout</a>
                    </div>
                ) : (
                    <a href="/login" class="text-xs bg-blue-600 px-3 py-1.5 rounded hover:bg-blue-500">Login</a>
                )}
            </nav>
            <main class="p-4 max-w-3xl mx-auto">{props.children}</main>
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

    // User ပိုင်တဲ့ File တွေကို ဆွဲထုတ်မယ်
    const iter = kv.list<FileData>({ prefix: ["files", user.username] }, { reverse: true });
    const files = [];
    for await (const res of iter) files.push(res.value);

    return c.html(
        <Layout user={user}>
            {/* UPLOAD BOX */}
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg mb-8">
                <h2 class="font-bold text-lg mb-4 flex items-center gap-2"><i class="fa-solid fa-cloud-arrow-up text-blue-400"></i> Upload New File</h2>
                <form action="/upload" method="post" enctype="multipart/form-data" class="space-y-4">
                    
                    {/* Server Selection */}
                    <div>
                        <label class="text-xs font-bold text-gray-400 uppercase mb-2 block">Choose Server</label>
                        <div class="grid grid-cols-2 gap-4">
                            <label class="cursor-pointer">
                                <input type="radio" name="server" value="1" class="peer sr-only" checked />
                                <div class="p-3 bg-slate-900 border border-slate-700 rounded-lg peer-checked:border-blue-500 peer-checked:bg-blue-500/10 text-center transition hover:bg-slate-700">
                                    <span class="font-bold text-sm block">Server 1</span>
                                    <span class="text-[10px] text-gray-500">abc-iqowoq</span>
                                </div>
                            </label>
                            <label class="cursor-pointer">
                                <input type="radio" name="server" value="2" class="peer sr-only" />
                                <div class="p-3 bg-slate-900 border border-slate-700 rounded-lg peer-checked:border-yellow-500 peer-checked:bg-yellow-500/10 text-center transition hover:bg-slate-700">
                                    <span class="font-bold text-sm block">Server 2</span>
                                    <span class="text-[10px] text-gray-500">lugyicloud</span>
                                </div>
                            </label>
                        </div>
                    </div>

                    {/* File Input */}
                    <div class="border-2 border-dashed border-slate-600 rounded-xl p-6 text-center hover:border-blue-500 transition bg-slate-900/50">
                        <input type="file" name="file" required class="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-xs file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700"/>
                        <p class="text-[10px] text-gray-500 mt-2">Max Size: 20MB (Free) | 1GB (VIP)</p>
                    </div>

                    <button class="w-full bg-gradient-to-r from-blue-600 to-cyan-500 py-3 rounded-xl font-bold shadow-lg hover:brightness-110">Start Upload</button>
                </form>
            </div>

            {/* FILE LIST */}
            <h3 class="font-bold text-gray-400 mb-4 text-sm uppercase">Your Files ({files.length})</h3>
            <div class="space-y-3">
                {files.map(f => (
                    <div class="bg-slate-800 p-4 rounded-lg border border-slate-700 flex justify-between items-center group hover:border-slate-600 transition">
                        <div class="flex items-center gap-3 overflow-hidden">
                            <div class={`w-10 h-10 rounded-lg flex items-center justify-center text-lg ${f.server === '1' ? 'bg-blue-500/10 text-blue-400' : 'bg-yellow-500/10 text-yellow-400'}`}>
                                <i class={`fa-solid ${f.name.match(/\.(jpg|png|jpeg)$/i) ? 'fa-image' : 'fa-file-video'}`}></i>
                            </div>
                            <div class="min-w-0">
                                <p class="font-bold text-sm truncate text-white">{f.name}</p>
                                <p class="text-[10px] text-gray-500">
                                    Server {f.server} • {f.size} • {new Date(f.uploadedAt).toLocaleDateString()}
                                </p>
                            </div>
                        </div>
                        <div class="flex gap-2">
                            <a href={f.downloadUrl} target="_blank" class="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white text-xs rounded font-bold transition">
                                <i class="fa-solid fa-download"></i> DL
                            </a>
                            <button onclick={`navigator.clipboard.writeText('${f.downloadUrl}'); alert('Copied!')`} class="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-gray-300 hover:text-white text-xs rounded transition">
                                <i class="fa-regular fa-copy"></i>
                            </button>
                        </div>
                    </div>
                ))}
                {files.length === 0 && <p class="text-center text-gray-600 py-10">No files uploaded yet.</p>}
            </div>
        </Layout>
    );
});

// 🔥 UPLOAD HANDLER
app.post("/upload", async (c) => {
    const cookie = getCookie(c, "auth");
    if(!cookie) return c.redirect("/login");
    const user = await getUser(cookie);
    if(!user) return c.redirect("/login");

    const body = await c.req.parseBody();
    const file = body['file'];
    const serverChoice = String(body['server']); // 1 or 2

    if (file instanceof File) {
        // Simple 20MB Limit Check for Deno Deploy
        if (file.size > 20 * 1024 * 1024) {
             return c.text("Error: File too large! (Max 20MB for direct upload)", 400);
        }

        try {
            // ၁. နာမည်ကို Unique ဖြစ်အောင် လုပ်မယ် (Link တွေ မထပ်အောင်)
            // ဥပမာ: my_video.mp4 -> uuid-my_video.mp4
            const safeName = file.name.replace(/[^a-zA-Z0-9.-]/g, "_"); // Special chars ဖယ်မယ်
            const objectKey = `${crypto.randomUUID()}-${safeName}`;
            
            // ၂. Server ရွေးပြီး Upload တင်မယ်
            const client = serverChoice === "1" ? s3Server1 : s3Server2;
            const bucket = serverChoice === "1" ? Deno.env.get("R2_1_BUCKET_NAME") : Deno.env.get("R2_2_BUCKET_NAME");

            const buffer = await file.arrayBuffer();
            await client.send(new PutObjectCommand({
                Bucket: bucket,
                Key: objectKey,
                Body: new Uint8Array(buffer),
                ContentType: file.type,
            }));

            // ၃. Vercel Link ပြန်ထုတ်ပေးမယ် (မိတ်ဆွေလိုချင်တဲ့ ပုံစံအတိုင်း)
            let finalUrl = "";
            if (serverChoice === "1") {
                finalUrl = `${DOMAIN_1}${objectKey}`;
            } else {
                finalUrl = `${DOMAIN_2}${objectKey}`;
            }

            // ၄. Database ထဲ သိမ်းမယ်
            const fileData: FileData = {
                id: crypto.randomUUID(),
                name: file.name,
                size: (file.size / 1024 / 1024).toFixed(2) + " MB",
                server: serverChoice as "1" | "2",
                downloadUrl: finalUrl,
                uploadedAt: Date.now()
            };

            await kv.set(["files", user.username, fileData.id], fileData);

            return c.redirect("/");

        } catch (e: any) {
            return c.text("Upload Failed: " + e.message, 500);
        }
    }
    return c.text("No file selected", 400);
});

// 🔥 AUTH (Simple)
app.get("/login", (c) => c.html(<Layout title="Login"><div class="max-w-sm mx-auto mt-20 bg-slate-800 p-8 rounded-xl border border-slate-700"><h1 class="text-2xl font-bold mb-6 text-center text-yellow-500">Gold Storage</h1><form action="/login" method="post" class="space-y-4"><input name="username" placeholder="Username" required class="w-full p-3 bg-slate-900 border border-slate-700 rounded-lg text-white" /><button class="w-full bg-blue-600 py-3 rounded-lg font-bold">Login / Create</button></form></div></Layout>));
app.post("/login", async (c) => {
    const { username } = await c.req.parseBody();
    const u = String(username).trim();
    if(!u) return c.redirect("/login");
    
    // Auto Register if not exists
    const existing = await getUser(u);
    if (!existing) {
        await kv.set(["users", u], { username: u, passwordHash: "demo", role: "free" });
    }
    
    setCookie(c, "auth", u, { path: "/", maxAge: 86400 * 30 });
    return c.redirect("/");
});
app.get("/logout", (c) => { deleteCookie(c, "auth"); return c.redirect("/login"); });

Deno.serve(app.fetch);
