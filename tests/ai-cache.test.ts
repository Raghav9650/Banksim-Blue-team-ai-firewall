import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { FirewallRequest } from "../src/types";

const mocks = vi.hoisted(() => ({
  generateContent: vi.fn(),
}));

vi.mock("@google/genai", () => ({
  GoogleGenAI: class {
    models = { generateContent: mocks.generateContent };
  },
}));

import { analyzeWithGemini } from "../server/ai-analyzer";

const analysisResponse = {
  threatDetected: false,
  threatCategory: "NONE",
  riskScore: 0,
  confidence: 0.99,
  explanation: "No suspicious activity was identified.",
  recommendedAction: "ALLOW",
};

describe("Gemini analysis cache", () => {
  beforeEach(() => {
    vi.stubEnv("GEMINI_API_KEY", "test-api-key");
    mocks.generateContent.mockReset();
    mocks.generateContent.mockResolvedValue({
      text: JSON.stringify(analysisResponse),
    });
  });

  afterAll(() => {
    vi.unstubAllEnvs();
  });

  it("reuses analysis when only encryption and idempotency metadata changes", async () => {
    const request: FirewallRequest = {
      target_tool: "TRANSFER_SIMULATION",
      amount: "25.00",
      target_identifier: "ACCT-2048",
      memo: "Unique cache reuse test request",
    };

    const firstRequest = {
      ...request,
      encrypted_audit_payload: "first-encrypted-envelope",
    };
    const secondRequest = {
      ...request,
      encrypted_audit_payload: "second-encrypted-envelope",
      idempotency_key: "6765b32b-0959-45ad-80ec-1088b695ca6e",
    };
    const firstResult = await analyzeWithGemini(firstRequest);
    const secondResult = await analyzeWithGemini(secondRequest);

    expect(firstResult.status).toBe("LIVE_AI");
    expect(secondResult.status).toBe("LIVE_AI");
    expect(secondResult.durationMs).toBe(0);
    expect(mocks.generateContent).toHaveBeenCalledOnce();
  });

  it("runs a new analysis when threat-relevant request content changes", async () => {
    const request: FirewallRequest = {
      target_tool: "MEMO_REVIEW",
      memo: "Unique cache invalidation test request",
    };

    await analyzeWithGemini(request);
    await analyzeWithGemini({ ...request, memo: "Changed threat-relevant memo" });

    expect(mocks.generateContent).toHaveBeenCalledTimes(2);
  });
});
