"use server";

import {
  loginUser,
  // verifyOTP,
  // resendOTP,
  // socialLogin,
  // logoutUser,
  // sendEmailVerification,
  // verifyEmail,
  // sendPasswordReset,
  // verifyResetLink,
  // resetPassword,
  // createUser,
} from "@/libs/api";
// import {
//   setSessionCookie,
//   deleteSessionCookie,
//   deleteCSRFCookie,
//   getRefreshTokenFromSession,
// } from '@/libs/cookie';
import type {
  LoginRequest,
  // OTPRequest,
  // ResendOTPRequest,
  // SocialLoginRequest,
  // EmailVerifyRequest,
  // PasswordResetRequest,
  // PasswordResetConfirm,
  // UserCreateRequest,
  // SessionResponseSuccess,
} from "@/types/types";

export async function loginAction(
  data: LoginRequest,
): Promise<{ success: true; user_id: number } | { error: string }> {
  const result = await loginUser(data);
  if ("error" in result && result.error) return { error: result.error };
  if ("user_id" in result) return { success: true, user_id: result.user_id };
  return { error: "Login failed" };
}

// export async function verifyOTPAction(
//   data: OTPRequest
// ): Promise<{ success: true; user_role: string } | { error: string }> {
//   const result = await verifyOTP(data);
//   if ('error' in result && result.error) return { error: result.error };
//   const session = result as SessionResponseSuccess;
//   if (!session.access_token) return { error: 'Invalid OTP response' };
//   await setSessionCookie(session);
//   return { success: true, user_role: session.user_role || '' };
// }

// export async function resendOTPAction(
//   data: ResendOTPRequest
// ): Promise<{ success: true } | { error: string }> {
//   const result = await resendOTP(data);
//   if ('error' in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function socialLoginAction(
//   provider: string,
//   token?: string
// ): Promise<{ success: true; user_role: string } | { error: string }> {
//   if (!token) return { error: 'No token provided' };
//   const data: SocialLoginRequest = {
//     token,
//     provider: provider as 'google' | 'facebook' | 'github',
//   };
//   const result = await socialLogin(data);
//   if ('error' in result && result.error) return { error: result.error };
//   const session = result as SessionResponseSuccess;
//   await setSessionCookie(session);
//   return { success: true, user_role: session.user_role || '' };
// }

// export async function logoutAction(): Promise<
//   { success: true } | { error: string }
// > {
//   const refresh = await getRefreshTokenFromSession();
//   if (refresh) await logoutUser({ refresh });
//   await deleteSessionCookie();
//   await deleteCSRFCookie();
//   return { success: true };
// }

// export async function registerAction(
//   data: UserCreateRequest
// ): Promise<{ success: true } | { error: string }> {
//   const result = await createUser(data);
//   if ('error' in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function sendEmailVerificationAction(
//   data: EmailVerifyRequest
// ): Promise<{ success: true } | { error: string }> {
//   const result = await sendEmailVerification(data);
//   if ('error' in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function verifyEmailAction(
//   token: string,
//   expiry: string
// ): Promise<{ success: true } | { error: string }> {
//   const result = await verifyEmail(token, expiry);
//   if ('error' in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function forgotPasswordAction(
//   data: PasswordResetRequest
// ): Promise<{ success: true } | { error: string }> {
//   const result = await sendPasswordReset(data);
//   if ('error' in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function verifyResetLinkAction(
//   token: string,
//   expiry: string
// ): Promise<{ success: true } | { error: string }> {
//   const result = await verifyResetLink(token, expiry);
//   if ('error' in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function resetPasswordAction(
//   token: string,
//   expiry: string,
//   data: PasswordResetConfirm
// ): Promise<{ success: true } | { error: string }> {
//   const result = await resetPassword(token, expiry, data);
//   if ('error' in result && result.error) return { error: result.error };
//   return { success: true };
// }
