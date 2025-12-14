const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const USERS_FILE = path.join(__dirname, 'users.json');

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname)); // Serve static files (HTML, CSS, JS)

// Ensure users.json exists
if (!fs.existsSync(USERS_FILE)) {
    const defaultUsers = {
        'Weinsther': {
            password: hashPassword('Ivomasseguro266'),
            token: null
        }
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
}

// Helper: Hash Password
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// API Routes

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Faltan credenciales' });
    }

    let users = JSON.parse(fs.readFileSync(USERS_FILE));

    // Migration helper: if old format, convert to new
    if (users[username] && typeof users[username] === 'string') {
        users[username] = { password: users[username], token: null };
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); // Save migrated data
    }

    const hashedFn = hashPassword(password);
    const userObj = users[username];

    if (userObj && userObj.password === hashedFn) {
        let token = null;

        // Generate Token for Admin
        if (username === 'Weinsther') {
            token = crypto.randomUUID();
            users[username].token = token;
            fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        }

        const userCredits = username === 'Weinsther' ? 999999 : (userObj.credits !== undefined ? userObj.credits : 100);

        return res.json({
            success: true,
            username: username,
            token: token, // Send token to client
            credits: userCredits
        });
    } else {
        return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }
});

// Create User (Secure Admin Only)
app.post('/api/create-user', (req, res) => {
    const { username, password } = req.body;
    const clientToken = req.headers['authorization']; // Expect "Bearer <token>" or just <token>

    if (!clientToken) {
        return res.status(401).json({ success: false, message: 'Token requerido' });
    }

    // Clean token (remove Bearer if present)
    const token = clientToken.replace('Bearer ', '');

    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    const admin = users['Weinsther'];

    // Verify Admin Token
    if (!admin || !admin.token || admin.token !== token) {
        return res.status(403).json({ success: false, message: 'Token inválido o expirado' });
    }

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Datos incompletos' });
    }

    if (users[username]) {
        return res.status(400).json({ success: false, message: 'El usuario ya existe' });
    }

    users[username] = {
        password: hashPassword(password),
        token: null,
        credits: 100
    };

    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

    res.json({ success: true, message: 'Usuario creado' });
});

// Get User Info (Credits)
app.post('/api/user-info', (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username requerido' });
    }

    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users[username];

    if (!user) {
        return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    const credits = username === 'Weinsther' ? 999999 : (user.credits !== undefined ? user.credits : 100);

    res.json({ success: true, credits: credits });
});

// Proxy for KeyScore (Password Check - Free)
app.post('/api/check-pass', async (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: "No password" });

    try {
        const response = await fetch("https://api.keysco.re/search", {
            method: "POST",
            headers: {
                "accept": "*/*",
                "authorization": "Bearer demo_key",
                "content-type": "application/json",
                "origin": "https://beta.keysco.re",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
            },
            body: JSON.stringify({
                "terms": [password],
                "types": ["password"],
                "source": "both",
                "wildcard": true,
                "operator": "LOGS"
            })
        });

        const data = await response.json();
        res.json(data);

    } catch (error) {
        console.error("KeyScore Pass Error:", error);
        res.status(500).json({ status: "Error", message: "KeyScore failed" });
    }
});

// Proxy for OsintDog (Unlock Password - Costs 1 Credit)
app.post('/api/unlock-pass', async (req, res) => {
    const { password, username } = req.body;

    if (!password || !username) return res.status(400).json({ error: "Missing data" });

    // 1. Check Credits
    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    if (!users[username]) return res.status(404).json({ error: "User not found" });

    if (username !== 'Weinsther') {
        const userCredits = users[username].credits !== undefined ? users[username].credits : 100;
        if (userCredits < 1) {
            return res.status(403).json({ success: false, message: "Créditos insuficientes" });
        }
    }

    try {
        // 2. Call OsintDog
        const response = await fetch("https://osintdog.com/api/keyscore/search", {
            method: "POST",
            headers: {
                "X-API-Key": "uow9X5UnSue211C7ILdkQuNmEgVP_rUiFOg0DNnk4hY",
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                "terms": [password],
                "types": ["password"],
                "source": "xkeyscore",
                "wildcard": false,
                "regex": false,
                "operator": "OR",
                "page": 1,
                "pagesize": 10000
            })
        });

        const data = await response.json();

        // 3. Deduct Credit
        if (username !== 'Weinsther') {
            const current = users[username].credits !== undefined ? users[username].credits : 100;
            users[username].credits = current - 1;
            fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        }

        const returnedCredits = username === 'Weinsther' ? 999999 : users[username].credits;
        res.json({ success: true, newCredits: returnedCredits, data: data });

    } catch (error) {
        console.error("OsintDog Pass Error:", error);
        res.status(500).json({ status: "Error", message: "Unlock failed" });
    }
});

// Proxy for OsintDog (Unlock UUID - Costs 1 Credit)
app.post('/api/unlock-uuid', async (req, res) => {
    const { uuid, username } = req.body;

    if (!uuid || !username) return res.status(400).json({ error: "Missing data" });

    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    if (!users[username]) return res.status(404).json({ error: "User not found" });

    if (username !== 'Weinsther') {
        const userCredits = users[username].credits !== undefined ? users[username].credits : 100;
        if (userCredits < 1) {
            return res.status(403).json({ success: false, message: "Créditos insuficientes" });
        }
    }

    try {
        const response = await fetch("https://osintdog.com/api/keyscore/search", {
            method: "POST",
            headers: {
                "X-API-Key": "uow9X5UnSue211C7ILdkQuNmEgVP_rUiFOg0DNnk4hY",
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                "terms": [uuid],
                "types": ["uuid"],
                "source": "xkeyscore",
                "wildcard": false,
                "regex": false,
                "operator": "OR",
                "page": 1,
                "pagesize": 10000
            })
        });

        const data = await response.json();

        if (username !== 'Weinsther') {
            const current = users[username].credits !== undefined ? users[username].credits : 100;
            users[username].credits = current - 1;
            fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        }

        const returnedCredits = username === 'Weinsther' ? 999999 : users[username].credits;
        res.json({ success: true, newCredits: returnedCredits, data: data });

    } catch (error) {
        console.error("OsintDog UUID Error:", error);
        res.status(500).json({ status: "Error", message: "Unlock failed" });
    }
});

// Proxy for Hash Cracking (HashMob API)
app.post('/api/crack', async (req, res) => {
    const { hash } = req.body;
    if (!hash) return res.status(400).json({ error: "No hash provided" });

    try {
        const response = await fetch("https://hashmob.net/api/v2/search", {
            method: "POST",
            headers: {
                "accept": "application/json, text/plain, */*",
                "accept-language": "es-ES,es;q=0.9,ru;q=0.8,bm;q=0.7",
                "content-type": "application/json",
                "cookie": "_ga=GA1.2.433718925.1753515641; session_id=eyJpdiI6Im1aRjZrc20vQ0RPcnFabU1vNCtRZ1E9PSIsInZhbHVlIjoiTW1IWmZOeE9IcStHU2ZEVnpMNE1aN0xVWmFUclZLeEVQUGZSN2g4bjVPSlJsVHB1WmUzdDJJYk9CSDFXN3hCTDFTN0g1dWw4VG84VlJFbGE5K3JrUFlmZlpBSTNrZHl3dzB4a1NiNEJPTkk9IiwibWFjIjoiOWE0MGY2ZTE0M2Y0NGUwOWZiMjhlOTYwNGJjMjhjZDRhYWFlOTQxOWI2Njc4MjE5YzViZjQxMTIzODE0NzE3NSIsInRhZyI6IiJ9; _gid=GA1.2.1509092354.1765607618; patreon_advertisement_shown=eyJpdiI6ImpXZHU0L1JQekp2UzdLaVM0NFdsWlE9PSIsInZhbHVlIjoiamsrZ2xJenh5a2twZ2xWdTFoSGp3cjY0QXJtaVl2MWF5R2hYV2NUdXh5R3k1QjNoOW5Ec2ROMXhBa285dGRJdCIsIm1hYyI6IjRmZjc5ZWNlMjAxNDRlZmNkYjdhZDAzYzRkMGU2OTk3Njg4NTYwOGE5N2U2NWY3YmMyOGFmMjZlYmJhNmM3MWIiLCJ0YWciOiIifQ%3D%3D; XSRF-TOKEN=eyJpdiI6Im94ektuN2NpNnRTT2pLU3VjYzk2SXc9PSIsInZhbHVlIjoiT0xyWG00YmdvVDNKZXc5WFlWNURPNWhYRFI3WlMxdlJqVVVqTXEwL1pRY3c0amxIdkFpbEtGUEVCSjJxaTZmNEg1aEtmd1BxSE1rTkhlME13Z202M01qWXVVTk45UlBBVUdQcTBwVXJnL1ZncXRVTFlmOVcrbWh2eUN0MHo3MVciLCJtYWMiOiI0OGEzZmNjNTk2ZDNkM2ZmMTliZjQ1ZjA3YjMxMzcyY2UwMDI1MDY5NWIwYTViYjUzYzA3ZmI5NzU0MGExYzUyIiwidGFnIjoiIn0%3D; _ga_X6KS2K3SVB=GS2.2.s1765703072$o4$g1$t1765703713$j55$l0$h0; hashmob_session=eyJpdiI6IlgybERoNy9DUi9Pa0sySU5FNTQ3c0E9PSIsInZhbHVlIjoicFpvSGpaMTlPcElGd0pqK1FseWdLN1hoeWpSR1RndUU4dzB0VTloRE1GSXRLMERXaDlNM2RQQWk1VGE5b0tNWjZDanJTOXhHVEw5U05MZy9lOE1OMzR0QlkvL0FGZUwxdEdwd3lpb3dZRjhweFkxOEhmbTUyT1BnaGhKblhrYmIiLCJtYWMiOiIwYTVmMzc1NzA0ZjI3ZGQwM2QzODg1OTEwNzEzOTQ2N2U3Mzk1NWRiMWQ1ZDAwM2I4YTEzZWJjNmFiNWU2ZmMzIiwidGFnIjoiIn0%3D",
                "origin": "https://hashmob.net",
                "priority": "u=1, i",
                "sec-ch-ua": "\"Google Chrome\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
                "x-xsrf-token": "eyJpdiI6Im94ektuN2NpNnRTT2pLU3VjYzk2SXc9PSIsInZhbHVlIjoiT0xyWG00YmdvVDNKZXc5WFlWNURPNWhYRFI3WlMxdlJqVVVqTXEwL1pRY3c0amxIdkFpbEtGUEVCSjJxaTZmNEg1aEtmd1BxSE1rTkhlME13Z202M01qWXVVTk45UlBBVUdQcTBwVXJnL1ZncXRVTFlmOVcrbWh2eUN0MHo3MVciLCJtYWMiOiI0OGEzZmNjNTk2ZDNkM2ZmMTliZjQ1ZjA3YjMxMzcyY2UwMDI1MDY5NWIwYTViYjUzYzA3ZmI5NzU0MGExYzUyIiwidGFnIjoiIn0="
            },
            body: JSON.stringify({ "hashes": [hash] })
        });

        const data = await response.json();
        res.json(data);

    } catch (error) {
        console.error("Proxy Error:", error);
        res.status(500).json({ status: "Error", message: "Proxy failed" });
    }
});

// Proxy for KeyScore (IP Check - Free)
app.post('/api/check-ip', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: "No IP" });

    try {
        const response = await fetch("https://api.keysco.re/search", {
            method: "POST",
            headers: {
                "accept": "*/*",
                "accept-language": "es-ES,es;q=0.9,ru;q=0.8,bm;q=0.7",
                "authorization": "Bearer demo_key",
                "content-type": "application/json",
                "origin": "https://beta.keysco.re",
                "priority": "u=1, i",
                "referer": "https://beta.keysco.re/",
                "sec-ch-ua": "\"Google Chrome\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-site",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
            },
            body: JSON.stringify({
                "terms": [ip],
                "types": ["ip"],
                "source": "both",
                "wildcard": true,
                "operator": "LOGS"
            })
        });

        const data = await response.json();
        res.json(data);

    } catch (error) {
        console.error("KeyScore Error:", error);
        res.status(500).json({ status: "Error", message: "KeyScore failed" });
    }
});

// Proxy for OsintDog (Unlock IP - Costs 1 Credit)
app.post('/api/unlock-ip', async (req, res) => {
    const { ip, username } = req.body; // Username needed to deduct credits

    if (!ip || !username) return res.status(400).json({ error: "Missing data" });

    // 1. Check Credits
    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    if (!users[username]) return res.status(404).json({ error: "User not found" });

    // Unlimited for Weinsther
    if (username === 'Weinsther') {
        // No deduction, just proceed
    } else {
        const userCredits = users[username].credits !== undefined ? users[username].credits : 100; // Default 100
        if (userCredits < 1) {
            return res.status(403).json({ success: false, message: "Créditos insuficientes" });
        }
    }

    try {
        // 2. Call OsintDog
        const response = await fetch("https://osintdog.com/api/keyscore/search", {
            method: "POST",
            headers: {
                "X-API-Key": "uow9X5UnSue211C7ILdkQuNmEgVP_rUiFOg0DNnk4hY",
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                "terms": [ip],
                "types": ["ip"],
                "source": "xkeyscore",
                "wildcard": false,
                "regex": false,
                "operator": "OR",
                "page": 1,
                "pagesize": 10000
            })
        });

        const data = await response.json();

        // 3. Deduct Credit Only on Success (Skip for Weinsther)
        if (username !== 'Weinsther') {
            const current = users[username].credits !== undefined ? users[username].credits : 100;
            users[username].credits = current - 1;
            fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        }

        const returnedCredits = username === 'Weinsther' ? 999999 : users[username].credits;
        res.json({ success: true, newCredits: returnedCredits, data: data });

    } catch (error) {
        console.error("OsintDog Error:", error);
        res.status(500).json({ status: "Error", message: "Unlock failed" });
    }
});

// Start Server
app.post('/api/ip-geo', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: "Missing IP" });

    try {
        const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query`);
        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error("Geo API Error:", error);
        res.status(500).json({ status: "Error", message: "Geo lookup failed" });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
