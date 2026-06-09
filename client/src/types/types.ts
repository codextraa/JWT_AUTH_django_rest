export interface SessionData {
  user_id: string;
  user_role: string;
  access_token: string;
  refresh_token: string;
  access_token_expiry: string;
}

export interface CSRFTokenData {
  csrf_token: string;
  csrf_token_expiry: string;
}

export interface ErrorResponse {
  error: string | undefined;
}

export interface CSRFTokenResponseSuccess {
  csrf_token: string | undefined;
  csrf_token_expiry: string | undefined;
}

export type CSRFTokenResponse = CSRFTokenResponseSuccess | ErrorResponse;

export interface SessionResponseSuccess {
  access_token: string | undefined;
  refresh_token: string | undefined;
  access_token_expiry: string | undefined;
  user_id: string | undefined;
  user_role: string | undefined;
  csrf_token: string | undefined;
  csrf_token_expiry: string | undefined;
}

export type SessionResponse = SessionResponseSuccess | ErrorResponse;
