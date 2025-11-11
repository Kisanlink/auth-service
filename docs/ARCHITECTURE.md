# Auth Service Architecture

## Overview

The auth-service is a **pure API client library** with **zero storage dependencies**. It follows functional programming principles and leaves all storage decisions to the consuming application.

## Storage Philosophy

### ❌ What Auth Service Does NOT Do
- Does NOT use localStorage
- Does NOT use sessionStorage
- Does NOT use Redux
- Does NOT use any storage mechanism
- Does NOT manage application state

### ✅ What Auth Service DOES
- Provides pure functions to call authentication APIs
- Accepts configuration with injectable `getAccessToken` callback
- Returns data from APIs
- Allows downstream services to handle storage

## Token Management Pattern

```typescript
// ❌ WRONG: Auth service managing storage
const authService = createAAAService({
  baseURL: 'https://api.example.com',
  // DON'T DO THIS - library shouldn't touch localStorage
  getAccessToken: () => localStorage.getItem('token')
});

// ✅ CORRECT: Downstream app manages storage
import { configureStore } from '@reduxjs/toolkit';
import createAAAService from 'auth-service';

// Redux slice managing auth state
const authSlice = createSlice({
  name: 'auth',
  initialState: { token: null },
  reducers: {
    setToken: (state, action) => {
      state.token = action.payload;
    }
  }
});

const store = configureStore({
  reducer: { auth: authSlice.reducer }
});

// Auth service reads from Redux store
const authService = createAAAService({
  baseURL: 'https://api.example.com',
  getAccessToken: () => store.getState().auth.token
});

// When login succeeds, store token in Redux
const response = await authService.auth.login({ ... });
store.dispatch(setToken(response.access_token));
```

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│  React Application (Downstream Consumer)                 │
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Redux Store (or other state management)         │   │
│  │  - Stores tokens                                 │   │
│  │  - Stores user data                              │   │
│  │  - Manages auth state                            │   │
│  └─────────────────────────────────────────────────┘   │
│                      │                                    │
│                      │ getAccessToken callback           │
│                      ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Auth Service (Pure API Client)                   │   │
│  │  - NO storage                                     │   │
│  │  - Just makes API calls                           │   │
│  │  - Returns data                                   │   │
│  └─────────────────────────────────────────────────┘   │
│                      │                                    │
│                      │ HTTP requests                     │
│                      ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Backend API (https://api.example.com)            │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Integration Example

### Setting Up With Redux

```typescript
// store/authSlice.ts
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import createAAAService from 'auth-service';

// Create auth service instance
const authService = createAAAService({
  baseURL: process.env.REACT_APP_API_URL,
  getAccessToken: () => {
    const state = store.getState();
    return state.auth.accessToken;
  }
});

// Async thunk for login
export const login = createAsyncThunk(
  'auth/login',
  async (credentials: { country_code: string; phone_number: string; password: string }) => {
    const response = await authService.auth.login(credentials);
    return response;
  }
);

// Auth slice
const authSlice = createSlice({
  name: 'auth',
  initialState: {
    accessToken: null,
    refreshToken: null,
    user: null,
    loading: false,
    error: null
  },
  reducers: {
    logout: (state) => {
      state.accessToken = null;
      state.refreshToken = null;
      state.user = null;
    }
  },
  extraReducers: (builder) => {
    builder
      .addCase(login.fulfilled, (state, action) => {
        state.accessToken = action.payload.access_token;
        state.refreshToken = action.payload.refresh_token;
        state.user = action.payload.user;
      })
      .addCase(login.rejected, (state, action) => {
        state.error = action.error.message;
      });
  }
});

export default authSlice.reducer;
```

### Using in Components

```typescript
// components/LoginForm.tsx
import { useDispatch } from 'react-redux';
import { login } from '../store/authSlice';

function LoginForm() {
  const dispatch = useDispatch();

  const handleSubmit = async (e) => {
    e.preventDefault();
    // Redux handles storage automatically
    await dispatch(login({
      country_code: '+1',
      phone_number: phoneNumber,
      password: password
    }));
  };

  return <form onSubmit={handleSubmit}>...</form>;
}
```

## Testing Without Storage

Tests use in-memory token management via `TestContext`:

```typescript
// tests/integration/auth/login.test.ts
import { TestContext } from '../../helpers/test-utils';

describe('Login Tests', () => {
  let context: TestContext;

  beforeEach(() => {
    // TestContext manages tokens in memory
    context = new TestContext();
  });

  it('should login successfully', async () => {
    const service = context.getService();

    const response = await service.auth.login({
      country_code: '+1',
      phone_number: '1234567890',
      password: 'password123'
    });

    // TestContext automatically captures and provides token
    expect(response.access_token).toBeDefined();
  });
});
```

## Benefits of This Architecture

1. **No Storage Coupling**: Library works with any storage mechanism (Redux, MobX, Zustand, memory, etc.)
2. **Testability**: Easy to test without mocking storage APIs
3. **Flexibility**: Downstream apps choose their own storage strategy
4. **Security**: No assumptions about where/how tokens are stored
5. **Simplicity**: Library does one thing well - API communication
6. **Composability**: Can be used in Node.js, React Native, or any JS environment

## Summary

- ✅ **Auth service**: Pure API client, no storage
- ✅ **Tests**: In-memory token management via TestContext
- ✅ **Downstream apps**: Responsible for storage (Redux/localStorage/etc.)
- ✅ **Integration**: Via `getAccessToken` callback pattern
- ✅ **Zero redundancy**: No duplicate storage code
