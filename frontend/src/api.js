import API_BASE_URL from './config';

let sessionId = null;

export function apiFetch(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (sessionId) headers['X-Session-ID'] = sessionId;

  return fetch(`${API_BASE_URL}${path}`, {
    ...options,
    credentials: 'include',
    headers,
  }).then(res => {
    const id = res.headers.get('X-Session-ID');
    if (id) sessionId = id;
    return res;
  });
}
