import { NextRequest } from "next/server";
import {
  BedrockRuntimeClient,
  ConverseCommand,
  type Message,
  type ContentBlock,
  type ToolConfiguration,
  type ToolResultContentBlock,
} from "@aws-sdk/client-bedrock-runtime";

const MODEL_ID = "us.anthropic.claude-sonnet-5";

const SYSTEM_PROMPT = `You are a sandbox assistant. You have access to an isolated Linux sandbox (Lambda MicroVM) where you can execute commands and manage files.

Available tools:
- execute_command: Run a shell command in the sandbox
- write_file: Write content to a file 
- read_file: Read content from a file
- list_files: List files in a directory

When the user gives you a task:
1. Break it into concrete steps
2. Use the tools to accomplish each step
3. Show the user what you did and the results

The sandbox has: Python 3, Node.js, git, curl, jq, and standard Linux tools.
Working directory is /tmp. Always use absolute paths.`;

const TOOL_CONFIG: ToolConfiguration = {
  tools: [
    {
      toolSpec: {
        name: "execute_command",
        description: "Execute a shell command in the sandbox. Returns stdout, stderr, and exit code.",
        inputSchema: { json: { type: "object", properties: { command: { type: "string", description: "The shell command to execute" }, cwd: { type: "string", description: "Working directory (default: /tmp)", default: "/tmp" } }, required: ["command"] } },
      },
    },
    {
      toolSpec: {
        name: "write_file",
        description: "Write content to a file in the sandbox.",
        inputSchema: { json: { type: "object", properties: { path: { type: "string", description: "Absolute file path" }, content: { type: "string", description: "File content to write" } }, required: ["path", "content"] } },
      },
    },
    {
      toolSpec: {
        name: "read_file",
        description: "Read content from a file in the sandbox.",
        inputSchema: { json: { type: "object", properties: { path: { type: "string", description: "Absolute file path to read" } }, required: ["path"] } },
      },
    },
    {
      toolSpec: {
        name: "list_files",
        description: "List files in a directory.",
        inputSchema: { json: { type: "object", properties: { path: { type: "string", description: "Directory path (default: /tmp)", default: "/tmp" } }, required: ["path"] } },
      },
    },
  ],
};

async function executeSandboxTool(
  toolName: string,
  toolInput: Record<string, string>,
  connection: { baseUrl: string; authHeaderName: string; authHeaderValue: string },
  origin: string
): Promise<{ result: string; exitCode?: number }> {
  const sandboxUrl = `${origin}/api/sandbox`;
  const body: Record<string, string> = {
    baseUrl: connection.baseUrl,
    authHeaderName: connection.authHeaderName,
    authHeaderValue: connection.authHeaderValue,
  };

  if (toolName === "execute_command") {
    Object.assign(body, { action: "execute", command: toolInput.command, cwd: toolInput.cwd || "/tmp" });
  } else if (toolName === "write_file") {
    Object.assign(body, { action: "write_file", path: toolInput.path, content: toolInput.content });
  } else if (toolName === "read_file") {
    Object.assign(body, { action: "read_file", path: toolInput.path });
  } else if (toolName === "list_files") {
    Object.assign(body, { action: "list_files", path: toolInput.path || "/tmp" });
  } else {
    return { result: `Unknown tool: ${toolName}` };
  }

  const resp = await fetch(sandboxUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await resp.json();
  if (data.error) return { result: `Error: ${data.error}`, exitCode: -1 };

  if (toolName === "execute_command") {
    return { result: (data.stdout || "") + (data.stderr || "") || "(no output)", exitCode: data.exitCode };
  }
  if (toolName === "write_file") {
    return { result: `Wrote ${(toolInput.content || "").length} bytes to ${toolInput.path}` };
  }
  if (toolName === "read_file") {
    return { result: data.content || "(empty file)" };
  }
  if (toolName === "list_files") {
    return {
      // nosemgrep: missing-template-string-indicator -- valid template literal, not a missing $
      result: (data.files || [])
        .map((f: { name: string; kind: string; size: number }) =>
          `${f.kind === "directory" ? "\u{1F4C1}" : "\u{1F4C4}"} ${f.name}${f.kind !== "directory" ? ` (${f.size} B)` : ""}`)
        .join("\n") || "(empty directory)",
    };
  }
  return { result: JSON.stringify(data) };
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { prompt, connection, history, stream: useStream } = body as {
    prompt: string;
    connection: { baseUrl: string; authHeaderName: string; authHeaderValue: string };
    history?: Array<{ role: string; content: string }>;
    stream?: boolean;
  };

  if (!prompt || !connection) {
    return new Response(JSON.stringify({ error: "Missing prompt or connection" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const origin = request.nextUrl.origin;
  const client = new BedrockRuntimeClient({ region: "us-east-1" });

  const messages: Message[] = [];
  if (history) {
    for (const msg of history) {
      if (msg.role === "user") messages.push({ role: "user", content: [{ text: msg.content }] });
      else if (msg.role === "assistant") messages.push({ role: "assistant", content: [{ text: msg.content }] });
    }
  }
  messages.push({ role: "user", content: [{ text: prompt }] });

  // If not streaming, use the old behavior
  if (!useStream) {
    return runNonStreaming(client, messages, connection, origin);
  }

  // Streaming: use SSE to send activity events in real time
  const encoder = new TextEncoder();
  const readable = new ReadableStream({
    async start(controller) {
      function send(event: string, data: Record<string, unknown>) {
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
      }

      const toolExecutions: Array<Record<string, unknown>> = [];
      let finalText = "";
      const MAX_TURNS = 10;

      try {
        for (let turn = 0; turn < MAX_TURNS; turn++) {
          send("activity", { actor: "bedrock", direction: "request", detail: turn === 0 ? `Converse(${prompt.slice(0, 60)}...)` : "Converse(tool_results)" });

          const resp = await client.send(
            new ConverseCommand({
              modelId: MODEL_ID,
              system: [{ text: SYSTEM_PROMPT }],
              messages,
              toolConfig: TOOL_CONFIG,
            })
          );

          const assistantContent = resp.output?.message?.content || [];
          messages.push({ role: "assistant", content: assistantContent });

          const toolUseBlocks = assistantContent.filter((b: ContentBlock) => "toolUse" in b);

          for (const block of assistantContent) {
            if ("text" in block && block.text) {
              finalText += (finalText ? "\n" : "") + block.text;
              send("activity", { actor: "bedrock", direction: "response", detail: `text: ${block.text.slice(0, 80)}...` });
            }
          }

          if (toolUseBlocks.length === 0) {
            send("activity", { actor: "bedrock", direction: "response", detail: "Done (no more tools)" });
            break;
          }

          send("activity", { actor: "bedrock", direction: "response", detail: `${toolUseBlocks.length} tool call(s)` });

          const toolResults: ContentBlock[] = [];
          for (const block of toolUseBlocks) {
            if (!("toolUse" in block) || !block.toolUse) continue;
            const { toolUseId, name, input: toolInput } = block.toolUse;
            const inputObj = toolInput as Record<string, string>;

            const shortInput = name === "execute_command" ? inputObj.command?.slice(0, 80) :
              name === "write_file" ? `${inputObj.path} (${(inputObj.content || "").length}B)` :
              name === "read_file" ? inputObj.path :
              name === "list_files" ? inputObj.path : JSON.stringify(inputObj).slice(0, 60);

            send("activity", { actor: "microvm", direction: "request", detail: `${name}(${shortInput})` });

            const start = Date.now();
            const result = await executeSandboxTool(name!, inputObj, connection, origin);
            const duration = Date.now() - start;

            send("activity", {
              actor: "microvm",
              direction: "response",
              detail: `${result.exitCode !== undefined ? `exit=${result.exitCode} ` : ""}${result.result.slice(0, 100)}`,
              duration,
            });

            toolExecutions.push({ tool: name!, input: inputObj, output: result.result, exitCode: result.exitCode, duration });
            const resultContent: ToolResultContentBlock[] = [{ text: result.result }];
            toolResults.push({ toolResult: { toolUseId, content: resultContent } });
          }

          messages.push({ role: "user", content: toolResults });
          send("activity", { actor: "bedrock", direction: "request", detail: `Sending ${toolResults.length} tool result(s)` });
        }
      } catch (err) {
        send("error", { message: `${err}` });
      }

      // Final result
      send("done", { text: finalText, toolExecutions });
      controller.close();
    },
  });

  return new Response(readable, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}

// Non-streaming fallback (original behavior)
async function runNonStreaming(
  client: BedrockRuntimeClient,
  messages: Message[],
  connection: { baseUrl: string; authHeaderName: string; authHeaderValue: string },
  origin: string
) {
  const toolExecutions: Array<Record<string, unknown>> = [];
  let finalText = "";
  const MAX_TURNS = 10;

  try {
    for (let turn = 0; turn < MAX_TURNS; turn++) {
      const resp = await client.send(
        new ConverseCommand({ modelId: MODEL_ID, system: [{ text: SYSTEM_PROMPT }], messages, toolConfig: TOOL_CONFIG })
      );
      const assistantContent = resp.output?.message?.content || [];
      messages.push({ role: "assistant", content: assistantContent });
      const toolUseBlocks = assistantContent.filter((b: ContentBlock) => "toolUse" in b);
      for (const block of assistantContent) {
        if ("text" in block && block.text) finalText += (finalText ? "\n" : "") + block.text;
      }
      if (toolUseBlocks.length === 0) break;

      const toolResults: ContentBlock[] = [];
      for (const block of toolUseBlocks) {
        if (!("toolUse" in block) || !block.toolUse) continue;
        const { toolUseId, name, input: toolInput } = block.toolUse;
        const start = Date.now();
        const result = await executeSandboxTool(name!, toolInput as Record<string, string>, connection, origin);
        toolExecutions.push({ tool: name!, input: toolInput, output: result.result, exitCode: result.exitCode, duration: Date.now() - start });
        toolResults.push({ toolResult: { toolUseId, content: [{ text: result.result }] } });
      }
      messages.push({ role: "user", content: toolResults });
    }
  } catch (err) {
    return new Response(JSON.stringify({ text: `Error calling Bedrock: ${err}`, toolExecutions: [] }), {
      status: 502,
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(JSON.stringify({ text: finalText, toolExecutions }), {
    headers: { "Content-Type": "application/json" },
  });
}
