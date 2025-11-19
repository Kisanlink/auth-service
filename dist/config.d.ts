export interface AuthServiceConfig {
    baseURL: string;
    defaultHeaders?: Record<string, string>;
    getAccessToken?: () => string | undefined;
}
