const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const ROOMS_DIR = path.join(DATA_DIR, 'rooms');
const METADATA_PATH = path.join(DATA_DIR, 'metadata.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(ROOMS_DIR)) fs.mkdirSync(ROOMS_DIR);
if (!fs.existsSync(METADATA_PATH)) fs.writeFileSync(METADATA_PATH, JSON.stringify({}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin === 'https://nxchat.zone.id') {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }

    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "connect-src 'self'; " +
        "frame-src 'none'; " +
        "frame-ancestors 'none';"
    );
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-XSS-Protection", "1; mode=block");

    next();
});

app.use('/static', express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'pages', 'index.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'pages', 'about.html')));
app.get('/create', (req, res) => res.sendFile(path.join(__dirname, 'pages', 'create.html')));
app.get('/join', (req, res) => res.sendFile(path.join(__dirname, 'pages', 'join.html')));

app.get('/room/:id', (req, res) => {
    const roomId = req.params.id;
    const metadata = JSON.parse(fs.readFileSync(METADATA_PATH, 'utf8'));
    
    if (!metadata[roomId] || Date.now() > metadata[roomId].expiry) {
        return res.redirect('/join?error=expired_or_not_found');
    }
    res.sendFile(path.join(__dirname, 'pages', 'room.html'));
});

const powChallenges = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [txId, data] of powChallenges.entries()) {
        if (now > data.expires) powChallenges.delete(txId);
    }
}, 60000);

app.get('/api/pow/step1', (req, res) => {
    const { txId } = req.query;
    if (!txId) return res.status(400).json({ error: "Missing txId" });
    const s1 = crypto.randomBytes(8).toString('hex');
    const existing = powChallenges.get(txId) || { expires: Date.now() + 300000 };
    existing.s1 = s1;
    powChallenges.set(txId, existing);
    res.json({ s1 });
});

app.get('/api/pow/step2', (req, res) => {
    const { txId } = req.query;
    if (!txId) return res.status(400).json({ error: "Missing txId" });
    const s2 = crypto.randomBytes(8).toString('hex');
    const existing = powChallenges.get(txId) || { expires: Date.now() + 300000 };
    existing.s2 = s2;
    powChallenges.set(txId, existing);
    res.json({ s2 });
});

app.get('/api/pow/step3', (req, res) => {
    const { txId } = req.query;
    if (!txId) return res.status(400).json({ error: "Missing txId" });
    const s3 = crypto.randomBytes(8).toString('hex');
    const existing = powChallenges.get(txId) || { expires: Date.now() + 300000 };
    existing.s3 = s3;
    powChallenges.set(txId, existing);
    res.json({ s3 });
});

app.post('/api/room/create', (req, res) => {
    const { txId, powKey, id, name, duration, aiEnabled } = req.body;

    if (!txId || !powKey || !id || !name || !duration) {
        return res.status(400).json({ error: "Missing parameters" });
    }

    if (!/^[a-zA-Z0-9]{4}$/.test(id)) {
        return res.status(400).json({ error: "ID must be a 4-digit alphanumeric value" });
    }

    if (name.length > 20) {
        return res.status(400).json({ error: "Room name too long" });
    }

    const challenge = powChallenges.get(txId);
    if (!challenge || !challenge.s1 || !challenge.s2 || !challenge.s3) {
        return res.status(400).json({ error: "Verification challenge expired or incomplete" });
    }

    const rawString = challenge.s1 + challenge.s2 + challenge.s3;
    const expectedKey = crypto.createHash('sha256').update(rawString).digest('hex');

    if (powKey !== expectedKey) {
        return res.status(403).json({ error: "Human verification failed" });
    }

    powChallenges.delete(txId);

    const metadata = JSON.parse(fs.readFileSync(METADATA_PATH, 'utf8'));
    const now = Date.now();
    if (metadata[id] && now < metadata[id].expiry) {
        return res.status(409).json({ error: "Room ID already exists" });
    }

    const durationMinutes = parseInt(duration, 10);
    const validDurations = [30, 60, 120, 480, 720, 1440];
    const finalDuration = validDurations.includes(durationMinutes) ? durationMinutes : 60;

    metadata[id] = {
        name: name,
        expiry: now + (finalDuration * 60 * 1000),
        maxMessages: finalDuration * 60,
        aiEnabled: !!aiEnabled
    };

    fs.writeFileSync(METADATA_PATH, JSON.stringify(metadata, null, 2));

    const roomFilePath = path.join(ROOMS_DIR, `${id}.json`);
    fs.writeFileSync(roomFilePath, JSON.stringify([]));

    res.json({ success: true, id });
});

app.get('/metadata/:id', (req, res) => {
    const roomId = req.params.id;
    const metadata = JSON.parse(fs.readFileSync(METADATA_PATH, 'utf8'));
    const info = metadata[roomId];

    if (!info || Date.now() > info.expiry) {
        return res.status(404).json({ error: "Room expired or not found" });
    }
    res.json({
        name: info.name,
        expiry: info.expiry,
        maxMessages: info.maxMessages
    });
});

app.get('/msgl/:id', (req, res) => {
    const roomId = req.params.id;
    const roomFilePath = path.join(ROOMS_DIR, `${roomId}.json`);

    if (!fs.existsSync(roomFilePath)) {
        return res.status(404).json({ error: "Room not found" });
    }

    try {
        const messages = JSON.parse(fs.readFileSync(roomFilePath, 'utf8'));
        res.json({ count: messages.length });
    } catch (e) {
        res.status(500).json({ error: "Failed to read messages" });
    }
});

app.get('/msgs/:id', (req, res) => {
    const roomId = req.params.id;
    const roomFilePath = path.join(ROOMS_DIR, `${roomId}.json`);

    if (!fs.existsSync(roomFilePath)) {
        return res.status(404).json({ error: "Room not found" });
    }

    try {
        const messages = JSON.parse(fs.readFileSync(roomFilePath, 'utf8'));
        res.json(messages);
    } catch (e) {
        res.status(500).json({ error: "Failed to load messages" });
    }
});

let lastAiReqTime = 0;

app.post('/api/message/:id', (req, res) => {
    const roomId = req.params.id;
    const { name, msg, isSystem } = req.body;
    const roomFilePath = path.join(ROOMS_DIR, `${roomId}.json`);

    if (!fs.existsSync(roomFilePath)) {
        return res.status(404).json({ error: "Room not found" });
    }

    const metadata = JSON.parse(fs.readFileSync(METADATA_PATH, 'utf8'));
    const roomInfo = metadata[roomId];

    if (!roomInfo || Date.now() > roomInfo.expiry) {
        return res.status(410).json({ error: "Room has expired" });
    }

    const messages = JSON.parse(fs.readFileSync(roomFilePath, 'utf8'));

    if (messages.length >= roomInfo.maxMessages) {
        return res.status(403).json({ error: "Message limit reached for this room" });
    }

    if (!isSystem && (!msg || msg.length > 200)) {
        return res.status(400).json({ error: "Message must be between 1 and 200 characters" });
    }

    const newMessage = {
        name: isSystem ? "System" : name.substring(0, 20),
        msg: msg,
        time: Date.now(),
        isSystem: !!isSystem
    };

    messages.push(newMessage);
    fs.writeFileSync(roomFilePath, JSON.stringify(messages, null, 2));

    res.json({ success: true });

    const lowercaseMsg = msg ? msg.toLowerCase() : "";
    const hasAiTag = lowercaseMsg.includes("@ai");
    const aiEnabled = roomInfo.aiEnabled;

    const triggerByEvery5 = aiEnabled && (messages.length % 5 === 0);
    const triggerByTag = !aiEnabled && hasAiTag;

    if (triggerByEvery5 || triggerByTag) {
        const now = Date.now();
        if (now - lastAiReqTime < 3000) {
            lastAiReqTime = now;
            
            const cooldownMsg = {
                name: "System",
                msg: "AI Cooldown active. (Rate-limited to 1 request every 3s). Please wait.",
                time: Date.now(),
                isSystem: true
            };
            const currentMsgs = JSON.parse(fs.readFileSync(roomFilePath, 'utf8'));
            currentMsgs.push(cooldownMsg);
            fs.writeFileSync(roomFilePath, JSON.stringify(currentMsgs, null, 2));
            return;
        }

        lastAiReqTime = now;

        const last5 = messages.slice(-5);
        const systemPrompt = "You are an AI assistant in a hacker-themed chatroom. Keep your response extremely brief (under 150 characters) and cyber-cool. Reply to the chat context.";

        const promptMessages = [
            { role: "system", content: systemPrompt }
        ];

        last5.forEach(m => {
            if (!m.isSystem) {
                promptMessages.push({
                    role: m.name === "AI" ? "assistant" : "user",
                    content: `[${m.name}]: ${m.msg}`
                });
            }
        });

        fetch("https://hnd1.aihub.zeabur.ai/v1/chat/completions", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${process.env.APIKEY}`
            },
            body: JSON.stringify({
                model: "llama-3.1-8b",
                messages: promptMessages
            })
        })
        .then(aiRes => {
            if (!aiRes.ok) throw new Error("Zeabur AI Hub error");
            return aiRes.json();
        })
        .then(data => {
            let aiText = data.choices[0]?.message?.content || "";
            aiText = aiText.trim().substring(0, 200);

            if (aiText) {
                const latestMessages = JSON.parse(fs.readFileSync(roomFilePath, 'utf8'));
                latestMessages.push({
                    name: "AI",
                    msg: aiText,
                    time: Date.now(),
                    isSystem: false
                });
                fs.writeFileSync(roomFilePath, JSON.stringify(latestMessages, null, 2));
            }
        })
        .catch(err => {
            console.error(err);
        });
    }
});

setInterval(() => {
    try {
        const metadata = JSON.parse(fs.readFileSync(METADATA_PATH, 'utf8'));
        const now = Date.now();
        let changed = false;

        for (const roomId in metadata) {
            if (now > metadata[roomId].expiry) {
                const fileToDel = path.join(ROOMS_DIR, `${roomId}.json`);
                if (fs.existsSync(fileToDel)) {
                    fs.unlinkSync(fileToDel);
                }
                delete metadata[roomId];
                changed = true;
            }
        }

        if (changed) {
            fs.writeFileSync(METADATA_PATH, JSON.stringify(metadata, null, 2));
        }
    } catch (e) {
        console.error(e);
    }
}, 30 * 60 * 1000);

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
