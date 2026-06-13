import { ApiClient } from "./apiClient";
// import { getRefreshTokenFromSession } from "./cookie";
import {
  CSRFTokenResponse,
  SessionResponse,
  LoginRequest,
  LoginResponse,
  // OTPRequest,
  // ResendOTPRequest,
  // SocialLoginRequest,
  // LogoutRequest,
  // EmailVerifyRequest,
  // PhoneOTPRequest,
  // PasswordResetRequest,
  // PasswordResetConfirm,
  // UserCreateRequest,
  // UserUpdateRequest,
  // UserDetail,
  // PaginatedUsers,
  ErrorResponse,
} from "@/types/types";


const HTTPS = process.env.HTTPS === "true";
const API_URL_OLD = HTTPS
  ? process.env.API_BASE_HTTPS_OLD_URL
  : process.env.API_BASE_URL;
const apiClientOld = new ApiClient(API_URL_OLD || "");

// const API_URL = HTTPS
//   ? process.env.API_BASE_HTTPS_URL
//   : process.env.API_BASE_URL;
// const apiClient = new ApiClient(API_URL || "");

export const getCSRFToken = async (): Promise<CSRFTokenResponse> => {
  return apiClientOld.get("/get-csrf-token/");
};

export const refreshToken = async (data: {
  refresh: string;
}): Promise<SessionResponse> => {
  return await apiClientOld.post("/token/refresh/", data);
};


export const loginUser = async (
  data: LoginRequest,
): Promise<LoginResponse | ErrorResponse> => {
  return apiClientOld.post("/login/", data);
};

// export const verifyOTP = async (
//   data: OTPRequest,
// ): Promise<SessionResponse> => {
//   return apiClient.post("/token/", data);
// };

// export const resendOTP = async (
//   data: ResendOTPRequest,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.post("/resend-otp/", data);
// };

// export const socialLogin = async (
//   data: SocialLoginRequest,
// ): Promise<SessionResponse> => {
//   return apiClient.post("/social-auth/", data);
// };

// export const logoutUser = async (
//   data: LogoutRequest,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.post("/logout/", data);
// };

// // ─── Email Verification ───────────────────────────────────────
// export const sendEmailVerification = async (
//   data: EmailVerifyRequest,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.post("/verify-email/", data);
// };

// export const verifyEmail = async (
//   token: string,
//   expiry: string,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.get(`/verify-email/?token=${token}&expiry=${expiry}`);
// };

// // ─── Phone Verification ───────────────────────────────────────
// export const sendPhoneOTP = async (): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.post<{ success: string } | ErrorResponse>("/verify-phone/", null);
// };

// export const verifyPhone = async (
//   data: PhoneOTPRequest,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.patch("/verify-phone/", data);
// };

// // ─── Password Reset ───────────────────────────────────────────
// export const sendPasswordReset = async (
//   data: PasswordResetRequest,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.post("/reset-password/", data);
// };

// export const verifyResetLink = async (
//   token: string,
//   expiry: string,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.get(`/reset-password/?token=${token}&expiry=${expiry}`);
// };

// export const resetPassword = async (
//   token: string,
//   expiry: string,
//   data: PasswordResetConfirm,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.patch(
//     `/reset-password/?token=${token}&expiry=${expiry}`,
//     data,
//   );
// };

// // ─── Users ────────────────────────────────────────────────────
// export const listUsers = async (
//   page = 1,
//   pageSize = 10,
//   filters = "",
// ): Promise<PaginatedUsers | ErrorResponse> => {
//   return apiClient.get(`/users/?page=${page}&page_size=${pageSize}${filters}`);
// };

// export const getUser = async (
//   id: number,
// ): Promise<UserDetail | ErrorResponse> => {
//   return apiClient.get(`/users/${id}/`);
// };

// export const createUser = async (
//   data: UserCreateRequest,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.post("/users/", data);
// };

// export const updateUser = async (
//   id: number,
//   data: UserUpdateRequest,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.patch(`/users/${id}/`, data);
// };

// export const deleteUser = async (
//   id: number,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.delete(`/users/${id}/`);
// };

// export const activateUser = async (
//   id: number,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.post(`/users/${id}/activate/`, {});
// };

// export const deactivateUser = async (
//   id: number,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.post(`/users/${id}/deactivate/`, {});
// };

// export const uploadProfileImage = async (
//   id: number,
//   formData: FormData,
// ): Promise<{ success: string } | ErrorResponse> => {
//   return apiClient.patch(`/users/${id}/upload_image/`, formData, {}, true);
// };