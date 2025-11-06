export interface AuthServiceConfig {
  baseURL: string;
  defaultHeaders?: Record<string, string>;
  getAccessToken?: () => string | undefined;
}

function getEnvVar(key: string): string | undefined {
  try {
    // Vite/ESM (browser) - import.meta.env
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const viteEnv = (import.meta as any)?.env;
    if (viteEnv && typeof viteEnv[key] !== 'undefined') return String(viteEnv[key]);
  } catch {}

  try {
    // Node/SSR - process.env
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const nodeEnv = (typeof process !== 'undefined' && (process as any).env) ? (process as any).env : undefined;
    if (nodeEnv && typeof nodeEnv[key] !== 'undefined') return String(nodeEnv[key]);
  } catch {}

  try {
    // Optional window-provided env
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const winEnv = (typeof window !== 'undefined' && (window as any).__ENV__) ? (window as any).__ENV__ : undefined;
    if (winEnv && typeof winEnv[key] !== 'undefined') return String(winEnv[key]);
  } catch {}

  return undefined;
}

// Single place for all configuration
export const authServiceConfig: AuthServiceConfig = {
  baseURL: getEnvVar('VITE_AAA_SERVICE_ENDPOINT1') || getEnvVar('VITE_AAA_SERVICE_ENDPOINT') || 'http://localhost:8080',
  defaultHeaders: {
    'Content-Type': 'application/json'
  },
  // Get access token from localStorage (works in browser environment)
  getAccessToken: () => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('access_token') || undefined;
    }
    return undefined;
  }
};


