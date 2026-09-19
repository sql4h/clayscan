export const PRESETS = {
  anthropic: {
    shape: 'anthropic',
    url: 'https://api.anthropic.com/v1/messages',
    keyEnv: ['ANTHROPIC_API_KEY'],
    model: 'claude-sonnet-5',
    label: 'Anthropic (Claude)',
  },
  openai: {
    shape: 'openai',
    url: 'https://api.openai.com/v1/chat/completions',
    keyEnv: ['OPENAI_API_KEY'],
    model: 'gpt-4o-mini',
    label: 'OpenAI',
  },
  openrouter: {
    shape: 'openai',
    url: 'https://openrouter.ai/api/v1/chat/completions',
    keyEnv: ['OPENROUTER_API_KEY'],
    model: 'meta-llama/llama-3.1-70b-instruct',
    label: 'OpenRouter',
    extraHeaders: { 'HTTP-Referer': 'https://github.com/clayscan', 'X-Title': 'ClayScan' },
  },
  nim: {
    shape: 'openai',
    url: 'https://integrate.api.nvidia.com/v1/chat/completions',
    keyEnv: ['NVIDIA_API_KEY', 'NIM_API_KEY'],
    model: 'meta/llama-3.1-70b-instruct',
    label: 'NVIDIA NIM',
  },
  gemini: {
    shape: 'openai',

    url: 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions',
    keyEnv: ['GEMINI_API_KEY', 'GOOGLE_API_KEY'],
    model: 'gemini-1.5-flash',
    label: 'Google Gemini',
  },
  groq: {
    shape: 'openai',
    url: 'https://api.groq.com/openai/v1/chat/completions',
    keyEnv: ['GROQ_API_KEY'],
    model: 'llama-3.1-70b-versatile',
    label: 'Groq',
  },
  together: {
    shape: 'openai',
    url: 'https://api.together.xyz/v1/chat/completions',
    keyEnv: ['TOGETHER_API_KEY'],
    model: 'meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo',
    label: 'Together',
  },
  ollama: {
    shape: 'openai',
    url: 'http://localhost:11434/v1/chat/completions',
    keyEnv: [],
    model: 'llama3.1',
    label: 'Ollama (local)',
    noKey: true,
  },
};

function firstEnv(names) {
  for (const n of names) if (process.env[n]) return process.env[n];
  return null;
}

export function resolveProvider(overrides = {}) {
  const globalKey = overrides.apiKey || process.env.CLAYSCAN_AI_API_KEY;
  const globalUrl = overrides.baseUrl || process.env.CLAYSCAN_AI_BASE_URL;
  const globalModel = overrides.model || process.env.CLAYSCAN_MODEL;
  let name = (overrides.provider || process.env.CLAYSCAN_AI_PROVIDER || 'auto').toLowerCase();

  if (name === 'auto') {
    name =
      Object.keys(PRESETS).find((k) => PRESETS[k].keyEnv.length && firstEnv(PRESETS[k].keyEnv)) ||
      (globalUrl ? 'custom' : null) ||
      (globalKey ? 'openai' : null) ||
      'none';
  }

  if (name === 'none') return { name: 'none', shape: 'local' };

  if (name === 'custom') {
    return {
      name: 'custom',
      shape: (overrides.shape || process.env.CLAYSCAN_AI_SHAPE || 'openai'),
      url: globalUrl,
      apiKey: globalKey,
      model: globalModel || 'gpt-4o-mini',
      label: 'Custom endpoint',
    };
  }

  const preset = PRESETS[name];
  if (!preset) return { name: 'none', shape: 'local', error: `Unknown provider "${name}"` };

  const apiKey = globalKey || firstEnv(preset.keyEnv);
  if (!apiKey && !preset.noKey) {
    return { name, shape: 'local', missingKey: preset.keyEnv[0] || 'CLAYSCAN_AI_API_KEY', label: preset.label };
  }

  return {
    name,
    shape: preset.shape,
    url: globalUrl || preset.url,
    apiKey,
    model: globalModel || preset.model,
    label: preset.label,
    extraHeaders: preset.extraHeaders,
  };
}

export async function callModel(provider, { system, user, maxTokens = 1800 }) {
  if (provider.shape === 'anthropic') {
    const res = await fetch(provider.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': provider.apiKey,
        'anthropic-version': '2023-06-01',
        ...(provider.extraHeaders || {}),
      },
      body: JSON.stringify({
        model: provider.model,
        max_tokens: maxTokens,
        system,
        messages: [{ role: 'user', content: user }],
      }),
    });
    if (!res.ok) throw new Error(`${provider.label} HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const data = await res.json();
    return (data.content || []).map((b) => b.text || '').join('\n').trim();
  }

  const headers = { 'content-type': 'application/json', ...(provider.extraHeaders || {}) };
  if (provider.apiKey) headers.authorization = `Bearer ${provider.apiKey}`;
  const res = await fetch(provider.url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: provider.model,
      max_tokens: maxTokens,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    }),
  });
  if (!res.ok) throw new Error(`${provider.label} HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const data = await res.json();
  return (data.choices?.[0]?.message?.content || '').trim();
}
