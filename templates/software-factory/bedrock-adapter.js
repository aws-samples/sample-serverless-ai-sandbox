/**
 * Bedrock Proxy Adapter for Node.js AI SDK
 *
 * Bridges Node.js AI SDK to the egress proxy. Sends requests using raw
 * TCP to avoid Node.js http module's URL encoding (which encodes the colon
 * in model IDs like v1:0 to %3A, breaking the proxy's SigV4 re-signing).
 *
 * Usage:
 *   node bedrock-adapter.js &
 *   AWS_ENDPOINT_URL_BEDROCK_RUNTIME=http://127.0.0.1:9090 opencode
 */
const http = require("http");
const net = require("net");

const PROXY = (() => {
    const m = (process.env.http_proxy || "").match(/http:\/\/([^:]+):(\d+)/);
    if (!m) { console.error("No http_proxy"); process.exit(1); }
    return { host: m[1], port: parseInt(m[2]) };
})();
const LISTEN_PORT = parseInt(process.env.ADAPTER_PORT || "9090");
const BEDROCK_HOST = process.env.BEDROCK_HOST || "bedrock-runtime.us-east-1.amazonaws.com";

const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
        const body = Buffer.concat(chunks);
        // Forward-proxy style: full URL as the request line
        // Use raw TCP to avoid Node's URL encoding of colons
        const requestLine = req.method + " http://" + BEDROCK_HOST + req.url + " HTTP/1.1\r\n";
        const headers =
            "Host: " + BEDROCK_HOST + "\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: " + body.length + "\r\n" +
            "\r\n";

        const socket = net.createConnection(PROXY.port, PROXY.host, () => {
            socket.write(requestLine + headers);
            if (body.length > 0) socket.write(body);
        });

        let responseStarted = false;
        let headerBuf = "";
        socket.on("data", (data) => {
            if (!responseStarted) {
                headerBuf += data.toString();
                const headerEnd = headerBuf.indexOf("\r\n\r\n");
                if (headerEnd === -1) return;
                responseStarted = true;
                // Parse status line
                const statusLine = headerBuf.split("\r\n")[0];
                const statusCode = parseInt(statusLine.split(" ")[1]) || 502;
                // Parse headers
                const headerLines = headerBuf.substring(0, headerEnd).split("\r\n").slice(1);
                const respHeaders = {};
                for (const line of headerLines) {
                    const [k, ...v] = line.split(": ");
                    if (k) respHeaders[k.toLowerCase()] = v.join(": ");
                }
                res.writeHead(statusCode, respHeaders);
                // Write any body data that came with the header chunk
                const bodyStart = headerBuf.substring(headerEnd + 4);
                if (bodyStart.length > 0) res.write(bodyStart);
            } else {
                res.write(data);
            }
        });
        socket.on("end", () => res.end());
        socket.on("error", (err) => {
            console.error("Socket error:", err.message);
            if (!res.headersSent) res.writeHead(502);
            res.end(JSON.stringify({ error: err.message }));
        });
    });
});

server.listen(LISTEN_PORT, "127.0.0.1", () => {
    console.log("bedrock-adapter: " + LISTEN_PORT + " -> " + PROXY.host + ":" + PROXY.port + " -> " + BEDROCK_HOST);
});
