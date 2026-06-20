// "use server";

// import {
//   getUser,
//   listUsers,
//   updateUser,
//   deleteUser,
//   activateUser,
//   deactivateUser,
//   uploadProfileImage,
//   sendPhoneOTP,
//   verifyPhone,
// } from "@/libs/api";
// import { getUserIdFromSession } from "@/libs/cookie";
// import type {
//   UserUpdateRequest,
//   PhoneOTPRequest,
//   UserDetail,
//   PaginatedUsers,
// } from "@/types/types";

// export async function getCurrentUserAction(): Promise <
//   { success: true; data: UserDetail } | { error: string }
// > {
//   const userId = await getUserIdFromSession();
//   if (!userId) return { error: "Not authenticated" };
//   const result = await getUser(Number(userId));
//   if ("error" in result && result.error) return { error: result.error };
//   return { success: true, data: result as UserDetail };
// }

// export async function getUserAction(
//   id: number,
// ): Promise<{ success: true; data: UserDetail } | { error: string }> {
//   const result = await getUser(id);
//   if ("error" in result && result.error) return { error: result.error };
//   return { success: true, data: result as UserDetail };
// }

// export async function listUsersAction(
//   page = 1,
//   pageSize = 10,
//   filters = "",
// ): Promise<{ success: true; data: PaginatedUsers } | { error: string }> {
//   const result = await listUsers(page, pageSize, filters);
//   if ("error" in result && result.error) return { error: result.error };
//   return { success: true, data: result as PaginatedUsers };
// }

// export async function updateUserAction(
//   id: number,
//   data: UserUpdateRequest,
// ): Promise<{ success: true } | { error: string }> {
//   const result = await updateUser(id, data);
//   if ("error" in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function deleteUserAction(
//   id: number,
// ): Promise<{ success: true } | { error: string }> {
//   const result = await deleteUser(id);
//   if ("error" in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function activateUserAction(
//   id: number,
// ): Promise<{ success: true } | { error: string }> {
//   const result = await activateUser(id);
//   if ("error" in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function deactivateUserAction(
//   id: number,
// ): Promise<{ success: true } | { error: string }> {
//   const result = await deactivateUser(id);
//   if ("error" in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function uploadProfileImageAction(
//   id: number,
//   formData: FormData,
// ): Promise<{ success: true } | { error: string }> {
//   const result = await uploadProfileImage(id, formData);
//   if ("error" in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function sendPhoneOTPAction(): Promise <
//   { success: true } | { error: string }
// > {
//   const result = await sendPhoneOTP();
//   if ("error" in result && result.error) return { error: result.error };
//   return { success: true };
// }

// export async function verifyPhoneAction(
//   data: PhoneOTPRequest,
// ): Promise<{ success: true } | { error: string }> {
//   const result = await verifyPhone(data);
//   if ("error" in result && result.error) return { error: result.error };
//   return { success: true };
// }
