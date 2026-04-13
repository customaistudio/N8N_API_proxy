import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { n8nGet, scrubDeep } from "./common.js";

// ---------- Server ----------
const server = new McpServer({
  name: "n8n-readonly",
  version: "1.1.0",
});

server.tool(
  "list_workflows",
  "List all n8n workflows with their IDs, names, active status, and tags",
  {
    cursor: z
      .string()
      .max(512)
      .regex(/^[A-Za-z0-9+/=_-]+$/, "cursor must be a URL-safe token")
      .optional()
      .describe("Pagination cursor from a previous response"),
    limit: z
      .number()
      .int()
      .min(1)
      .max(250)
      .optional()
      .describe("Number of workflows to return (default 100, max 250)"),
    active: z.boolean().optional().describe("Filter by active status"),
  },
  async ({ cursor, limit, active }) => {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));
    if (active !== undefined) params.set("active", String(active));

    const query = params.toString();
    const data = await n8nGet(`/workflows${query ? `?${query}` : ""}`);

    const workflows = data.data.map((wf) => ({
      id: wf.id,
      name: wf.name,
      active: wf.active,
      tags: wf.tags?.map((t) => t.name) ?? [],
      createdAt: wf.createdAt,
      updatedAt: wf.updatedAt,
    }));

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { workflows, nextCursor: data.nextCursor ?? null },
            null,
            2
          ),
        },
      ],
    };
  }
);

// n8n workflow IDs are short alphanumeric strings.
// Strict format blocks path traversal and injection.
const WORKFLOW_ID_SCHEMA = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9]+$/, "Workflow ID must be alphanumeric");

server.tool(
  "get_workflow",
  "Get the full details of a specific n8n workflow by ID, including all nodes, connections, and settings (secrets are redacted)",
  {
    id: WORKFLOW_ID_SCHEMA.describe("The workflow ID"),
  },
  async ({ id }) => {
    const data = await n8nGet(`/workflows/${encodeURIComponent(id)}`);
    const scrubbed = scrubDeep(data);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(scrubbed, null, 2),
        },
      ],
    };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
