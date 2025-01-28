'use server';
import { verifyEmail, requestEmailVerification } from "@/libs/api";


export const verifyEmailAction = async (token, expiry) => {
  try {
    const response = await verifyEmail(token, expiry);

    if (response.error) {
      return { error: response.error };
    };
    
    return { success: true };
  } catch (error) {
    console.error(error);
    return { error: error.message || "Token expired or invalid." };
  };
};

export const requestEmailVerificationAction = async (formData) => {
  const data = {
    email: formData.get("email"),
  };

  try {
    const response = await requestEmailVerification(data);
    
    if (response.error) {
      return { error: response.error };
    };

    return { success: true }; 
  } catch (error) {
    console.error(error);
    return { error: error.message || "Failed to send verification link." }
  }
};