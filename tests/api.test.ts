import { describe, expect, it } from "vitest";
import { readBankSimApiJson } from "../src/api";

describe("BankSim API response handling", () => {
  it("returns valid JSON responses", async () => {
    const response = new Response(JSON.stringify({ status: "operational" }), {
      headers: { "Content-Type": "application/json" },
    });

    await expect(
      readBankSimApiJson<{ status: string }>(response, "/api/health"),
    ).resolves.toEqual({ status: "operational" });
  });

  it("explains when a Vercel API request was routed to an HTML page", async () => {
    const response = new Response("<!doctype html><html></html>", {
      headers: { "Content-Type": "text/html" },
      status: 200,
    });

    await expect(readBankSimApiJson(response, "/api/health")).rejects.toThrow(
      "BankSim API route /api/health returned an HTML page instead of JSON (HTTP 200).",
    );
  });

  it("surfaces JSON API error responses", async () => {
    const response = new Response(JSON.stringify({ error: "Sign in is required." }), {
      headers: { "Content-Type": "application/json" },
      status: 401,
    });

    await expect(readBankSimApiJson(response, "/api/logs")).rejects.toThrow(
      "Sign in is required.",
    );
  });
});
