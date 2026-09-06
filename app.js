const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();

// Vulnerability 1: Command Injection
app.get("/ping", (req, res) => {
    const host = req.query.host;

    exec("ping " + host, (error, stdout) => {
        if (error) {
            res.status(500).send("Command failed");
            return;
        }

        res.send(stdout);
    });
});


// Vulnerability 2: Path Traversal
app.get("/file", (req, res) => {
    const filename = req.query.filename;

    const filePath = path.join(__dirname, "files", filename);

    fs.readFile(filePath, "utf8", (error, data) => {
        if (error) {
            res.status(404).send("File not found");
            return;
        }

        res.send(data);
    });
});


// Vulnerability 3: Reflected Cross-Site Scripting
app.get("/hello", (req, res) => {
    const name = req.query.name;

    res.send("<html><body><h1>Hello " + name + "</h1></body></html>");
});


app.listen(3000, () => {
    console.log("Vulnerable application running on port 3000");
});
