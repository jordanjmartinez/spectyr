import API_BASE_URL from './config';

export function apiFetch(path, options = {}) {
  return fetch(`${API_BASE_URL}${path}`, {
    ...options,
    credentials: 'include',
  });
}
