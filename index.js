import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { n8nGet, scrubDeep } from "./common.js";

process.on("unhandledRejection", (reason) => {
  console.error("[FATAL] Unhandled rejection:", reason);
  process.exit(1);
});

// ---------- Server ----------
const server = new McpServer({
  name: "n8n-readonly",
  version: "1.1.0",
});

// ---------- Projects ----------
const PROJECT_ID_SCHEMA = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9_-]+$/, "Project ID must be alphanumeric (hyphens/underscores allowed)");

server.tool(
  "list_projects",
  "List all n8n projects (workspaces) with their IDs and names. Use project IDs to filter workflows and executions by project.",
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
      .describe("Number of projects to return (default 100, max 250)"),
  },
  async ({ cursor, limit }) => {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));

    const query = params.toString();
    const data = await n8nGet(`/projects${query ? `?${query}` : ""}`);

    if (!Array.isArray(data.data)) {
      throw new Error("Unexpected response format from n8n API");
    }

    const projects = data.data.map((p) => ({
      id: p.id,
      name: p.name,
      type: p.type,
      createdAt: p.createdAt,
      updatedAt: p.updatedAt,
    }));

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { projects, nextCursor: data.nextCursor ?? null },
            null,
            2
          ),
        },
      ],
    };
  }
);

server.tool(
  "list_workflows",
  "List all n8n workflows with their IDs, names, active status, and tags. Optionally filter by project ID to see workflows across different projects.",
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
    projectId: PROJECT_ID_SCHEMA.optional().describe(
      "Filter workflows by project ID (use list_projects to get project IDs)"
    ),
  },
  async ({ cursor, limit, active, projectId }) => {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));
    if (active !== undefined) params.set("active", String(active));
    if (projectId) params.set("projectId", projectId);

    const query = params.toString();
    const data = await n8nGet(`/workflows${query ? `?${query}` : ""}`);

    if (!Array.isArray(data.data)) {
      throw new Error("Unexpected response format from n8n API");
    }

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

// ---------- Executions ----------
const EXECUTION_STATUS_SCHEMA = z
  .enum(["error", "new", "running", "success", "waiting"])
  .optional()
  .describe("Filter by execution status");

server.tool(
  "list_executions",
  "List n8n executions with optional filters by workflow ID, status, and project ID",
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
      .describe("Number of executions to return (default 100, max 250)"),
    workflowId: WORKFLOW_ID_SCHEMA.optional().describe(
      "Filter executions by workflow ID"
    ),
    status: EXECUTION_STATUS_SCHEMA,
    projectId: PROJECT_ID_SCHEMA.optional().describe(
      "Filter executions by project ID (use list_projects to get project IDs)"
    ),
  },
  async ({ cursor, limit, workflowId, status, projectId }) => {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));
    if (workflowId) params.set("workflowId", workflowId);
    if (status) params.set("status", status);
    if (projectId) params.set("projectId", projectId);

    const query = params.toString();
    const data = await n8nGet(`/executions${query ? `?${query}` : ""}`);

    if (!Array.isArray(data.data)) {
      throw new Error("Unexpected response format from n8n API");
    }

    const executions = data.data.map((ex) => ({
      id: ex.id,
      workflowId: ex.workflowId,
      status: ex.status,
      startedAt: ex.startedAt,
      stoppedAt: ex.stoppedAt,
      finished: ex.finished,
    }));

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { executions, nextCursor: data.nextCursor ?? null },
            null,
            2
          ),
        },
      ],
    };
  }
);

const EXECUTION_ID_SCHEMA = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9]+$/, "Execution ID must be alphanumeric");

server.tool(
  "get_execution",
  "Get full details of a specific n8n execution by ID, including node results and timing (secrets are redacted)",
  {
    id: EXECUTION_ID_SCHEMA.describe("The execution ID"),
    includeData: z.boolean().optional().default(true).describe(
      "Whether to include the execution's detailed data (node inputs/outputs, error messages). Defaults to true."
    ),
  },
  async ({ id, includeData }) => {
    const params = new URLSearchParams();
    if (includeData !== false) params.set("includeData", "true");
    const query = params.toString();
    const data = await n8nGet(`/executions/${encodeURIComponent(id)}${query ? `?${query}` : ""}`);
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
