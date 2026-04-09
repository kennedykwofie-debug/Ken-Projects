// LLM Factory â creates the configured provider or returns null

import { AnthropicProvider } from './lib_llm_anthropic.mjs.mjs';
import { OpenAIProvider } from './lib_llm_openai.mjs.mjs';
import { OpenRouterProvider } from './lib_llm_openrouter.mjs.mjs';
import { GeminiProvider } from './lib_llm_gemini.mjs.mjs';
import { CodexProvider } from './lib_llm_codex.mjs.mjs';
import { MiniMaxProvider } from './lib_llm_minimax.mjs.mjs';
import { MistralProvider } from './lib_llm_mistral.mjs.mjs';
import { OllamaProvider } from './lib_llm_ollama.mjs.mjs';
import { GrokProvider } from './lib_llm_grok.mjs.mjs';

export { LLMProvider } from './lib_llm_provider.mjs.mjs';
export { AnthropicProvider } from './lib_llm_anthropic.mjs.mjs';
export { OpenAIProvider } from './lib_llm_openai.mjs.mjs';
export { OpenRouterProvider } from './lib_llm_openrouter.mjs.mjs';
export { GeminiProvider } from './lib_llm_gemini.mjs.mjs';
export { CodexProvider } from './lib_llm_codex.mjs.mjs';
export { MiniMaxProvider } from './lib_llm_minimax.mjs.mjs';
export { MistralProvider } from './lib_llm_mistral.mjs.mjs';
export { OllamaProvider } from './lib_llm_ollama.mjs.mjs';
export { GrokProvider } from './lib_llm_grok.mjs.mjs';

/**
 * Create an LLM provider based on config.
 * @param {{ provider: string|null, apiKey: string|null, model: string|null }} llmConfig
 * @returns {LLMProvider|null}
 */
export function createLLMProvider(llmConfig) {
  if (!llmConfig?.provider) return null;

  const { provider, apiKey, model } = llmConfig;

  switch (provider.toLowerCase()) {
    case "anthropic":
      return new AnthropicProvider({ apiKey, model });
    case "openai":
      return new OpenAIProvider({ apiKey, model });
    case "openrouter":
      return new OpenRouterProvider({ apiKey, model });
    case "gemini":
      return new GeminiProvider({ apiKey, model });
    case "codex":
      return new CodexProvider({ model });
    case "minimax":
      return new MiniMaxProvider({ apiKey, model });
    case "mistral":
      return new MistralProvider({ apiKey, model });
    case "ollama":
      return new OllamaProvider({ model, baseUrl: llmConfig.baseUrl });
    case 'grok':
      return new GrokProvider({ apiKey, model });
    default:
      console.warn(
        `[LLM] Unknown provider "${provider}". LLM features disabled.`,
      );
      return null;
  }
}
