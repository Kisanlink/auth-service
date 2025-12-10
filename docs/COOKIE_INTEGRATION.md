# HTTP Cookies Integration Guide

This guide explains how to integrate cookie-based authentication in downstream services consuming the auth-service library.

## Overview

The AAA service supports two authentication methods:

| Method | Use Case | Token Management |
|--------|----------|------------------|
| **Bearer Token** | API clients, mobile apps, server-to-server | Manual (via `getAccessToken`) |
| **HTTP Cookies** | Browser clients, SPAs | Automatic (browser handles) |

Both methods can coexist - the backend accepts tokens from either source.

---

## Quick Start

### Browser Client (Cookie Authentication)

```typescript
import createAAAService from '@kisanlink/auth-service';

// Create service with cookie support
const aaaService = createAAAService({
  baseURL: 'https://api.example.com',
  withCredentials: true,  // Enable cookies
});

// Login - cookies set automatically
await aaaService.auth.login({
  phone_number: '9876543210',
  country_code: '+91',
  password: 'your_password',
});

// All subsequent requests include cookies automatically
const users = await aaaService.users.list();

// Logout - cookies cleared
await aaaService.auth.logout();
```

### API Client (Bearer Token)

```typescript
import createAAAService from '@kisanlink/auth-service';

// Create service with token callback
const aaaService = createAAAService({
  baseURL: 'https://api.example.com',
  getAccessToken: () => store.getState().auth.accessToken,
});

// Login - store token manually
const response = await aaaService.auth.login({ ... });
store.dispatch(setToken(response.access_token));
```

---

## Cookie Details

### Cookie Names

| Cookie | Purpose | Expiry |
|--------|---------|--------|
| `auth_token` | Access token for API authentication | 1 hour |
| `refresh_token` | Token for obtaining new access tokens | 7 days |

### Security Attributes

Both cookies are configured with:
- `HttpOnly` - Not accessible via JavaScript (prevents XSS)
- `Secure` - HTTPS only in production (prevents MITM)
- `SameSite` - Varies by environment (CSRF protection)

#### Environment Configuration

| Environment | Secure | SameSite | Notes |
|-------------|--------|----------|-------|
| Production | `true` | `None` | Cross-origin support |
| Dev with CORS | `true` | `None` | localhost treated as secure |
| Local | `false` | `Lax` | Same-origin only |

---

## React Integration

### With Context API

```typescript
// context/AuthContext.tsx
import { createContext, useContext, useState, ReactNode } from 'react';
import createAAAService from '@kisanlink/auth-service';

const aaaService = createAAAService({
  baseURL: import.meta.env.VITE_API_URL,
  withCredentials: true,
});

interface AuthContextType {
  user: UserData | null;
  login: (phone: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserData | null>(null);

  const login = async (phone: string, password: string) => {
    const response = await aaaService.auth.login({
      phone_number: phone,
      country_code: '+91',
      password,
    });
    setUser(response.user);
  };

  const logout = async () => {
    await aaaService.auth.logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{
      user,
      login,
      logout,
      isAuthenticated: !!user,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};
```

### With Redux Toolkit

```typescript
// store/authSlice.ts
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import createAAAService from '@kisanlink/auth-service';
import type { UserData } from '@kisanlink/auth-service';

const aaaService = createAAAService({
  baseURL: import.meta.env.VITE_API_URL,
  withCredentials: true,
});

interface AuthState {
  user: UserData | null;
  loading: boolean;
  error: string | null;
}

const initialState: AuthState = {
  user: null,
  loading: false,
  error: null,
};

export const login = createAsyncThunk(
  'auth/login',
  async (credentials: { phone: string; password: string }) => {
    const response = await aaaService.auth.login({
      phone_number: credentials.phone,
      country_code: '+91',
      password: credentials.password,
    });
    return response;
  }
);

export const logout = createAsyncThunk('auth/logout', async () => {
  await aaaService.auth.logout();
});

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(login.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(login.fulfilled, (state, action) => {
        state.loading = false;
        state.user = action.payload.user;
      })
      .addCase(login.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Login failed';
      })
      .addCase(logout.fulfilled, (state) => {
        state.user = null;
      });
  },
});

export default authSlice.reducer;
```

### Using in Components

```typescript
// components/LoginForm.tsx
import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
// or with Redux:
// import { useDispatch } from 'react-redux';
// import { login } from '../store/authSlice';

export function LoginForm() {
  const [phone, setPhone] = useState('');
  const [password, setPassword] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await login(phone, password);
      // Redirect to dashboard
    } catch (error) {
      // Handle error
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="tel"
        value={phone}
        onChange={(e) => setPhone(e.target.value)}
        placeholder="Phone number"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      <button type="submit">Login</button>
    </form>
  );
}
```

---

## Token Refresh Strategy

### Automatic Refresh with Interceptor Pattern

```typescript
// utils/authInterceptor.ts
import createAAAService from '@kisanlink/auth-service';

const aaaService = createAAAService({
  baseURL: import.meta.env.VITE_API_URL,
  withCredentials: true,
});

let isRefreshing = false;
let refreshSubscribers: ((success: boolean) => void)[] = [];

function subscribeToRefresh(callback: (success: boolean) => void) {
  refreshSubscribers.push(callback);
}

function onRefreshComplete(success: boolean) {
  refreshSubscribers.forEach((callback) => callback(success));
  refreshSubscribers = [];
}

export async function handleUnauthorized(
  mpin: string,
  refreshToken: string,
  retryRequest: () => Promise<any>
): Promise<any> {
  if (isRefreshing) {
    return new Promise((resolve, reject) => {
      subscribeToRefresh((success) => {
        if (success) {
          resolve(retryRequest());
        } else {
          reject(new Error('Session expired'));
        }
      });
    });
  }

  isRefreshing = true;

  try {
    await aaaService.auth.refresh({
      mpin,
      refresh_token: refreshToken,
    });
    onRefreshComplete(true);
    return retryRequest();
  } catch (error) {
    onRefreshComplete(false);
    // Redirect to login
    window.location.href = '/login';
    throw error;
  } finally {
    isRefreshing = false;
  }
}
```

---

## CORS Configuration

For cookies to work cross-origin, ensure your backend CORS is configured:

### Required Server Headers

```
Access-Control-Allow-Origin: https://your-frontend.com  # NOT *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Cookies not sent | `withCredentials` not set | Add `withCredentials: true` |
| CORS error | Origin is `*` | Set specific origin |
| Cookies not stored | `SameSite` mismatch | Check environment settings |
| 401 after login | Secure cookie over HTTP | Use HTTPS or local dev mode |

---

## Security Best Practices

### Do's

1. **Always use HTTPS in production** - Required for `Secure` cookies
2. **Implement proper logout** - Always call `/api/v1/auth/logout`
3. **Handle token expiry** - Implement refresh logic
4. **Use environment-specific configs** - Different settings for dev/prod

### Don'ts

1. **Don't store tokens in localStorage** - Use cookies for browser clients
2. **Don't expose tokens in URLs** - Use POST for authentication
3. **Don't skip logout** - Clears server-side session
4. **Don't use wildcard CORS** - Specify exact origins

---

## Troubleshooting

### Cookies Not Being Set

1. Check browser DevTools → Application → Cookies
2. Verify `Set-Cookie` headers in Network tab
3. Ensure `withCredentials: true` is set
4. Check for browser third-party cookie blocking

### 401 Errors After Login

1. Verify cookies are being sent (Network tab → Request Headers)
2. Check cookie expiry
3. Ensure same domain or proper CORS setup
4. Verify `SameSite` and `Secure` attributes match environment

### CORS Errors

1. Check `Access-Control-Allow-Origin` is specific (not `*`)
2. Verify `Access-Control-Allow-Credentials: true`
3. Ensure preflight requests succeed
4. Check browser console for detailed error messages

---

## Migration from Bearer Tokens

If migrating from explicit token management to cookies:

### Before (Bearer Tokens)

```typescript
const aaaService = createAAAService({
  baseURL: 'https://api.example.com',
  getAccessToken: () => localStorage.getItem('token'),
});

const response = await aaaService.auth.login({ ... });
localStorage.setItem('token', response.access_token);
```

### After (Cookies)

```typescript
const aaaService = createAAAService({
  baseURL: 'https://api.example.com',
  withCredentials: true,  // Just add this
});

await aaaService.auth.login({ ... });
// No manual token storage needed!
```

---

## API Reference

### Cookie Constants

```typescript
import { COOKIE_NAMES, COOKIE_DEFAULTS } from '@kisanlink/auth-service';

console.log(COOKIE_NAMES.AUTH_TOKEN);      // 'auth_token'
console.log(COOKIE_NAMES.REFRESH_TOKEN);   // 'refresh_token'
console.log(COOKIE_DEFAULTS.AUTH_TOKEN_MAX_AGE);     // 3600
console.log(COOKIE_DEFAULTS.REFRESH_TOKEN_MAX_AGE);  // 604800
```

### CookieConfig Type

```typescript
import type { CookieConfig, CookieSameSite } from '@kisanlink/auth-service';

// Available in login response
const response = await aaaService.auth.login({ ... });
if (response.cookie_config) {
  console.log(response.cookie_config.secure);     // true/false
  console.log(response.cookie_config.same_site);  // 'Strict' | 'Lax' | 'None'
}
```
