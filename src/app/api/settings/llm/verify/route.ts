import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-guard";
import { createLlmClient } from "@/lib/llm-gateway";
import { z } from "zod";

const verifySchema = z.object({
  llmProvider: z.string(),
  llmBaseUrl: z.string(),
  llmModel: z.string(),
  llmApiKey: z.string().optional(),
});

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  try {
    const body = await req.json();
    const data = verifySchema.parse(body);

    // Skip verification for Ollama (local, no API key needed)
    if (data.llmProvider.toLowerCase() === "ollama") {
      try {
        const client = createLlmClient({
          provider: data.llmProvider,
          baseUrl: data.llmBaseUrl,
          model: data.llmModel,
        });

        // Test Ollama connectivity with a simple generate request
        const response = await (client.client as any).generate({
          model: data.llmModel,
          prompt: "Say OK",
          stream: false,
        });

        if (response) {
          return NextResponse.json({
            success: true,
            message: "Ollama connection verified",
          });
        }

        return NextResponse.json(
          {
            success: false,
            error: "Ollama returned unexpected response",
          },
          { status: 400 }
        );
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        // Extract just the error message, not HTML content
        const message = errorMsg.includes("<!DOCTYPE")
          ? `Ollama is not running at ${data.llmBaseUrl}`
          : `Ollama connection failed: ${errorMsg}`;

        return NextResponse.json(
          {
            success: false,
            error: message,
          },
          { status: 400 }
        );
      }
    }

    // For API-based providers, test with a simple completion request
    if (!data.llmApiKey) {
      return NextResponse.json(
        {
          success: false,
          error: "API key is required for this provider",
        },
        { status: 400 }
      );
    }

    try {
      const client = createLlmClient({
        provider: data.llmProvider,
        baseUrl: data.llmBaseUrl,
        apiKey: data.llmApiKey,
        model: data.llmModel,
      });

      // Test API with a simple completion
      const response = await (client.client as any).chat.completions.create({
        model: data.llmModel,
        messages: [
          {
            role: "user",
            content: "Say OK",
          },
        ],
        max_tokens: 10,
      });

      if (response.choices && response.choices[0]) {
        return NextResponse.json({
          success: true,
          message: `${data.llmProvider} API key verified successfully`,
        });
      }

      return NextResponse.json(
        {
          success: false,
          error: "API returned unexpected response",
        },
        { status: 400 }
      );
    } catch (error) {
      let errorMessage = error instanceof Error ? error.message : "Unknown error";

      // Improve error messages for common scenarios
      if (errorMessage.includes("401") || errorMessage.includes("Unauthorized")) {
        errorMessage = "Invalid API key or authentication failed";
      } else if (errorMessage.includes("404") || errorMessage.includes("Not Found")) {
        errorMessage = "Endpoint not found. Check your base URL";
      } else if (errorMessage.includes("connection") || errorMessage.includes("ECONNREFUSED")) {
        errorMessage = `Cannot connect to ${data.llmBaseUrl}. Check if the server is running`;
      }

      return NextResponse.json(
        {
          success: false,
          error: errorMessage,
        },
        { status: 400 }
      );
    }
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        {
          success: false,
          error: "Invalid input",
          details: error.issues,
        },
        { status: 400 }
      );
    }
    return NextResponse.json(
      {
        success: false,
        error: "Verification failed",
      },
      { status: 500 }
    );
  }
}
