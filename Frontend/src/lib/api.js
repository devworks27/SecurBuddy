const API_BASE = import.meta.env.VITE_API_BASE ?? '';

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });

  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (body?.detail) detail = body.detail;
    } catch {
      // response had no JSON body; keep the status-based message
    }
    throw new Error(detail);
  }

  return response.json();
}

export function getHealth() {
  return request('/api/health');
}

export function getDataset() {
  return request('/api/dataset');
}

export function analyze({ rawContent = '', datasetId = null }) {
  return request('/api/analyze', {
    method: 'POST',
    body: JSON.stringify({ raw_content: rawContent, dataset_id: datasetId }),
  });
}

/**
 * Streams a chat reply via SSE over POST. EventSource cannot send a body, so we
 * read the response stream directly and parse `data:` frames ourselves.
 */
export async function streamChat({ history, userMessage, analysisContext }, handlers = {}) {
  const { onToken, onError, onDone } = handlers;

  let response;
  try {
    response = await fetch(`${API_BASE}/api/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        history,
        user_message: userMessage,
        analysis_context: analysisContext,
      }),
    });
  } catch {
    onError?.('Could not reach the SecurBuddy API. Is the backend running on port 8000?');
    onDone?.();
    return;
  }

  if (!response.ok || !response.body) {
    onError?.(`Chat stream failed (${response.status}).`);
    onDone?.();
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const frames = buffer.split('\n\n');
      buffer = frames.pop() ?? '';

      for (const frame of frames) {
        const line = frame.trim();
        if (!line.startsWith('data: ')) continue;

        const payload = line.slice(6);
        if (payload === '[DONE]') {
          onDone?.();
          return;
        }

        try {
          const event = JSON.parse(payload);
          if (event.text) onToken?.(event.text);
          else if (event.error) onError?.(event.error);
        } catch {
          // ignore malformed frame rather than killing the stream
        }
      }
    }
  } catch {
    onError?.('The connection dropped mid-stream.');
  } finally {
    onDone?.();
  }
}