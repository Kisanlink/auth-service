export interface UserRoleRef {
  id: string;
  role: { id: string; name: string };
}

export interface UserData {
  id: string;
  name?: string;
  phone_number?: string;
  roles: UserRoleRef[];
}

export interface LoginRequest {
  country_code?: string;
  phone_number: string;
  password: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
}

export interface AuthLoginResponse {
  access_token: string;
  refresh_token: string;
  user: UserData;
  permissions?: string[];
}

export interface RefreshRequest {
  mpin: string;
  refresh_token: string;
}

export interface PermissionEvaluationRequest {
  user_id: string;
  permission: string;
  context?: Record<string, unknown>;
}

export interface PermissionEvaluationResult {
  allowed: boolean;
  reasons?: string[];
}





