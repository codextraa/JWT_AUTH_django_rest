import React from "react";

// ─── Session, Pre-Auth & CSRF Data ──────────────────────────────────────
export interface SessionData {
  user_id: string;
  user_role: string;
  access_token: string;
  refresh_token: string;
  access_token_expiry: string;
}

export interface PreAuthData {
  pre_auth_token: string;
}

export interface CSRFTokenData {
  csrf_token: string;
  csrf_token_expiry: string;
}

// ─── API Response Types ───────────────────────────────────────
export interface SuccessResponse {
  success: string | undefined;
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

export interface PreAuthResponseSuccess {
  success: string | undefined;
  pre_auth_token: string | undefined;
}

export type SessionResponse =
  | SessionResponseSuccess
  | PreAuthResponseSuccess
  | ErrorResponse;

// ─── Auth Request Types ───────────────────────────────────────
export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  success: string;
  otp: boolean;
  user_id: number;
}

// export interface OTPRequest {
//   user_id: number;
//   otp: string;
// }

// export interface ResendOTPRequest {
//   user_id: number;
// }

// export interface RecaptchaRequest {
//   recaptcha_token: string;
// }

// export interface SocialLoginRequest {
//   token: string;
//   provider: "google" | "facebook" | "github";
// }

// export interface LogoutRequest {
//   refresh: string;
// }

// // ─── Email / Phone Verification Types ─────────────────────────
// export interface EmailVerifyRequest {
//   email: string;
// }

// export interface PhoneOTPRequest {
//   otp: string;
// }

// // ─── Password Reset Types ──────────────────────────────────────
// export interface PasswordResetRequest {
//   email: string;
// }

// export interface PasswordResetConfirm {
//   password: string;
//   c_password: string;
// }

// // ─── User Types ───────────────────────────────────────────────
// export interface UserList {
//   id: number;
//   username: string;
//   email: string;
//   is_active: boolean;
//   is_staff: boolean;
// }

// export interface UserDetail {
//   id: number;
//   email: string;
//   username: string;
//   first_name: string;
//   last_name: string;
//   phone_number: string;
//   profile_img: string;
//   slug: string;
//   is_active: boolean;
//   is_staff: boolean;
//   is_superuser: boolean;
//   is_email_verified: boolean;
//   is_phone_verified: boolean;
// }

// export interface UserCreateRequest {
//   email: string;
//   password: string;
//   c_password: string;
//   username?: string;
//   first_name?: string;
//   last_name?: string;
//   phone_number?: string;
//   is_staff?: boolean;
// }

// export interface UserUpdateRequest {
//   first_name?: string;
//   last_name?: string;
//   username?: string;
//   phone_number?: string;
// }

// export interface PaginatedUsers {
//   count: number;
//   total_pages: number;
//   next: string | null;
//   previous: string | null;
//   results: UserList[];
// }

// ─── Misc ─────────────────────────────────────────────────────
export interface ApiError {
  error: string | Record<string, unknown>;
}
export type UserRole = "User" | "Admin" | "SuperUser";

export interface ButtonProps {
  variant?: "primary" | "danger" | "secondary";
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  type?: "button" | "submit" | "reset";
  className?: string;
}

//! need to update this as well with buttons

export interface NavbarProps {
  isLoggedIn: boolean;
}
