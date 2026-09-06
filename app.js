const express = require("express");
const { execFile } = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();

// Simple in-memory rate limiter
const requests = new Map();

function rateLimit(req, res, next) {
    const ip = req.ip;
    const now = Date.now();
    const windowMs = 60 * 1000;
    const maxRequests = 10;

    const record = requests.get(ip) || {
        count: 0,
        startTime: now
    };

    if (now - record.startTime > windowMs) {
        record.count = 0;
        record.startTime = now;
    }

    record.count++;

    if (record.count > maxRequests) {
        return res.status(429).send("Too many requests");
    }

    requests.set(ip, record);
    next();
}


// FIX 1: Avoid shell command construction
app.get("/ping", rateLimit, (req, res) => {
    const host = req.query.host;

    // Only allow valid IPv4 addresses
    const ipv4 =
        /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    if (!ipv4.test(host)) {
        return res.status(400).send("Invalid IP address");
    }

    execFile("ping", [host], (error, stdout) => {
        if (error) {
            return res.status(500).send("Command failed");
        }

        res.type("text/plain").send(stdout);
    });
});


// FIX 2: Restrict file access to the files directory
app.get("/file", rateLimit, (req, res) => {
    const filename = req.query.filename;

    // Allow only simple text filenames
    if (!/^[a-zA-Z0-9_-]+\.txt$/.test(filename)) {
        return res.status(400).send("Invalid filename");
    }

    const baseDirectory = path.resolve(__dirname, "files");
    const filePath = path.resolve(baseDirectory, filename);

    if (!filePath.startsWith(baseDirectory + path.sep)) {
        return res.status(403).send("Access denied");
    }

    fs.readFile(filePath, "utf8", (error, data) => {
        if (error) {
            return res.status(404).send("File not found");
        }

        res.type("text/plain").send(data);
    });
});


// FIX 3: Prevent reflected XSS
app.get("/hello", (req, res) => {
    const name = req.query.name || "";

    // Return user input as text instead of constructing HTML
    res.type("text/plain").send("Hello " + name);
});


app.listen(3000, () => {
    console.log("Application running securely on port 3000");
});
