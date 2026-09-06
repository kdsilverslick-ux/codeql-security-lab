const express = require("express");
const { execFile } = require("child_process");
const path = require("path");

const app = express();


// FIX 1: Command injection
// Only approved hosts may be pinged.
const allowedHosts = {
    localhost: "127.0.0.1",
    google: "8.8.8.8"
};

app.get("/ping", (req, res) => {
    const requestedHost = req.query.host;

    if (!Object.prototype.hasOwnProperty.call(allowedHosts, requestedHost)) {
        return res.status(400).send("Invalid host");
    }

    const host = allowedHosts[requestedHost];

    execFile("ping", [host], (error, stdout) => {
        if (error) {
            return res.status(500).send("Command failed");
        }

        res.type("text/plain");
        return res.send(stdout);
    });
});


// FIX 2: Path traversal
// User input is mapped to predefined files instead of being used in a path.
const allowedFiles = {
    welcome: path.join(__dirname, "files", "welcome.txt"),
    help: path.join(__dirname, "files", "help.txt")
};

app.get("/file", (req, res) => {
    const requestedFile = req.query.filename;

    if (!Object.prototype.hasOwnProperty.call(allowedFiles, requestedFile)) {
        return res.status(400).send("Invalid file");
    }

    return res.sendFile(allowedFiles[requestedFile]);
});


// FIX 3: Reflected XSS
// Do not place user-controlled data into an HTML response.
app.get("/hello", (req, res) => {
    res.type("text/plain");
    return res.send("Hello! Welcome to the secure application.");
});


app.listen(3000, () => {
    console.log("Secure application running on port 3000");
});
