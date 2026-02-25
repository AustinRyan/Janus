const API_KEY = process.env.NEXT_PUBLIC_JANUS_API_KEY;

export function apiFetch(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const headers = new Headers(options.headers);
  if (API_KEY) {
    headers.set("Authorization", `Bearer ${API_KEY}`);
  }
  return fetch(url, { ...options, headers });
}
