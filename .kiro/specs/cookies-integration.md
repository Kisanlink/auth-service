# HTTP Cookies Integration Specification

## Overview

This specification defines how the auth-service API client library supports HTTP-only cookie-based authentication alongside traditional Bearer token authentication. The implementation follows the library's core principle of **zero storage coupling** - the library enables cookie support but leaves cookie management to downstream applications and browsers.

---

## 1. Cookie Configuration

### 1.1 Cookie Names and Lifetimes

| Cookie Name     | Purpose                               | Max-Age     | Default Path |
|-----------------|---------------------------------------|-------------|--------------|
| `auth_token`    | Access token for API authentication   | 3600s (1h)  | `/`          |
| `refresh_token` | Token for obtaining new access tokens | 604800s (7d)| `/`          |

### 1.2 Environment-Based Security Attributes

#### Production (`APP_ENV=production`)
```
HttpOnly: true    - Prevents XSS access to cookies
Secure: true      - HTTPS only transmission
SameSite: None    - Required for cross-origin requests with credentials
```

#### Development with CORS (`CORS_ORIGIN` set)
```
HttpOnly: true    - Prevents XSS access
Secure: true      - Required when SameSite=None (localhost is treated as secure)
SameSite: None    - Allows cross-origin cookie transmission
```

#### Local Development (same origin)
```
HttpOnly: true    - Prevents XSS access
Secure: false     - Allows HTTP for local development
SameSite: Lax     - Standard same-site policy
```

---

## 2. API Client Configuration

### 2.1 Extended Configuration Interface

The `ApiConfig` interface is extended to support cookie-based authentication:

```typescript
interface ApiConfig {
  baseURL: string;
  defaultHeaders?: Record<string, string>;
  getAccessToken?: () => string | undefined;

  // Cookie support
  withCredentials?: boolean;  // Enable cookie transmission
}
```

### 2.2 Configuration Options

| Option            | Type      | Default | Description                                      |
|-------------------|-----------|---------|--------------------------------------------------|
| `withCredentials` | `boolean` | `false` | When `true`, cookies are sent with requests      |

---

## 3. Authentication Flow with Cookies

### 3.1 Login Flow

```
Client                        API Server
  |                               |
  |  POST /api/v1/auth/login      |
  |  { phone_number, password }   |
  |------------------------------>|
  |                               |
  |  200 OK                       |
  |  Set-Cookie: auth_token=...   |
  |  Set-Cookie: refresh_token=...|
  |  { access_token, user, ... }  |
  |<------------------------------|
  |                               |
  |  (Browser stores cookies)     |
  |                               |
```

### 3.2 Authenticated Request Flow

```
Client                        API Server
  |                               |
  |  GET /api/v1/users            |
  |  Cookie: auth_token=...       |  (automatic with withCredentials)
  |------------------------------>|
  |                               |
  |  200 OK                       |
  |  { users: [...] }             |
  |<------------------------------|
```

### 3.3 Token Refresh Flow

```
Client                        API Server
  |                               |
  |  POST /api/v1/auth/refresh    |
  |  Cookie: refresh_token=...    |
  |  { mpin }                     |
  |------------------------------>|
  |                               |
  |  200 OK                       |
  |  Set-Cookie: auth_token=...   |  (new token)
  |  Set-Cookie: refresh_token=...|  (rotated)
  |<------------------------------|
```

### 3.4 Logout Flow

```
Client                        API Server
  |                               |
  |  POST /api/v1/auth/logout     |
  |  Cookie: auth_token=...       |
  |------------------------------>|
  |                               |
  |  200 OK                       |
  |  Set-Cookie: auth_token=; Max-Age=-1    |
  |  Set-Cookie: refresh_token=; Max-Age=-1 |
  |<------------------------------|
  |                               |
  |  (Browser clears cookies)     |
```

---

## 4. Authentication Middleware Behavior

The backend auth middleware accepts tokens from either source with the following priority:

1. **Authorization Header** (Bearer token) - checked first
2. **Cookie** (`auth_token`) - fallback if no header

This enables:
- Browser clients relying entirely on cookies (no manual token management)
- API clients using Bearer tokens (backward compatible)
- Hybrid applications using either method

---

## 5. CORS Requirements

For cookies to work cross-origin, the following CORS configuration is required:

### Server-Side Headers
```
Access-Control-Allow-Origin: <specific-origin>  (NOT *)
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
```

### Client-Side Requirements
- `withCredentials: true` in fetch/axios configuration
- Requests must be to a specific origin (not wildcard)

---

## 6. Security Considerations

### 6.1 Protection Mechanisms

| Attack Vector | Mitigation                                         |
|---------------|---------------------------------------------------|
| XSS           | `HttpOnly` flag prevents JavaScript access         |
| MITM          | `Secure` flag ensures HTTPS-only transmission      |
| CSRF          | `SameSite` attribute restricts cross-site requests |
| Token Theft   | Short-lived access tokens (1 hour)                 |

### 6.2 Cookie Security Best Practices

1. **Always use HTTPS in production** - Required for `Secure` cookies
2. **Implement CSRF protection** - `SameSite=None` increases CSRF exposure
3. **Token rotation on refresh** - Refresh tokens are rotated on each use
4. **Server-side logout** - Always call `/api/v1/auth/logout` to clear cookies

---

## 7. Implementation Guidelines

### 7.1 Browser Client (Recommended Pattern)

```typescript
// Create API client with cookie support
const apiClient = createApiClient({
  baseURL: 'https://api.example.com',
  withCredentials: true,  // Enable cookies
});

// Create service
const authService = createAuthService(apiClient);

// Login - cookies set automatically by browser
await authService.login({
  phone_number: '9876543210',
  country_code: '+91',
  password: 'password'
});

// Subsequent requests - cookies sent automatically
const users = await userService.list();

// Logout - cookies cleared by server
await authService.logout();
```

### 7.2 API Client (Bearer Token Pattern)

```typescript
// Create API client with token callback
const apiClient = createApiClient({
  baseURL: 'https://api.example.com',
  getAccessToken: () => store.getState().auth.accessToken,
});

// Tokens managed explicitly by application
const response = await authService.login({ ... });
store.dispatch(setToken(response.access_token));
```

### 7.3 Hybrid Pattern

```typescript
// Both cookie and token support
const apiClient = createApiClient({
  baseURL: 'https://api.example.com',
  withCredentials: true,
  getAccessToken: () => store.getState().auth.accessToken,
});

// Priority: Bearer token > Cookie
// If getAccessToken returns a value, it's used
// Otherwise, browser cookies are sent
```

---

## 8. Response Types

### 8.1 Login Response with Cookie Hints

```typescript
interface AuthLoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'Bearer';
  expires_in: number;        // Seconds until access_token expires (3600)
  user: UserData;
  permissions?: string[];

  // Cookie hints (informational, actual cookies set via Set-Cookie header)
  cookie_config?: {
    auth_token_max_age: number;     // 3600
    refresh_token_max_age: number;  // 604800
    secure: boolean;
    same_site: 'Strict' | 'Lax' | 'None';
  };
}
```

---

## 9. Error Handling

### 9.1 Cookie-Related Errors

| Status | Scenario                          | Action                           |
|--------|-----------------------------------|----------------------------------|
| 401    | Cookie expired or invalid         | Redirect to login                |
| 401    | No cookie and no Bearer token     | Redirect to login                |
| 403    | Cookie valid but insufficient     | Show permission denied           |

### 9.2 CORS Errors

If cookies aren't being sent/received, verify:
1. `withCredentials: true` is set
2. Server returns `Access-Control-Allow-Credentials: true`
3. `Access-Control-Allow-Origin` is specific (not `*`)
4. For `SameSite=None`, `Secure=true` is also set

---

## 10. Testing Considerations

### 10.1 Unit Tests
- Mock fetch with credential checking
- Verify `credentials: 'include'` is set when `withCredentials: true`

### 10.2 Integration Tests
- Test with actual cookies using test server
- Verify cookie attributes match environment

### 10.3 E2E Tests
- Test cross-origin cookie flow
- Verify login/logout cookie lifecycle

---

## Document Version

- **Version**: 1.0
- **Created**: December 2024
- **Status**: Implementation Ready
