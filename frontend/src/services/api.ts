import type { ScanResponse, ProvidersResponse } from "../types/security";

const API_BASE_URL = "http://localhost:8000";

export async function scanSourceCode(
  code: string,
  filename = "target.py",
  provider?: "groq" | "gemini" | "ollama"
): Promise<ScanResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code,
        filename,
        provider,
        include_diff_patches: true,
      }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Scan failed with status ${response.status}`);
    }

    return await response.json();
  } catch (err: any) {
    console.warn("Backend unavailable or connection failed, checking fallback:", err);
    throw err;
  }
}

export async function fetchProviders(): Promise<ProvidersResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/providers`);
    if (!response.ok) throw new Error("Failed to fetch provider status");
    return await response.json();
  } catch (err) {
    return {
      active_provider: "groq",
      available_providers: {
        groq: {
          name: "Groq Cloud (Free Tier)",
          model: "llama-3.3-70b-versatile",
          configured: true,
          is_primary: true,
        },
        gemini: {
          name: "Google Gemini (Free Tier)",
          model: "gemini-2.0-flash",
          configured: true,
          is_primary: false,
        },
        ollama: {
          name: "Ollama Local Fallback",
          model: "qwen2.5-coder:7b",
          configured: false,
          is_primary: false,
        },
      },
    };
  }
}

export async function verifyPatchSafety(
  originalCode: string,
  patchedCode: string,
  expectedSinkType?: string
) {
  const response = await fetch(`${API_BASE_URL}/api/v1/verify-patch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      original_code: originalCode,
      patched_code: patchedCode,
      expected_sink_type: expectedSinkType,
    }),
  });
  return await response.json();
}
