'use server';
import { 
  verifyEmail,
  requestEmailVerification,
  createUser
} from "@/libs/api";


export const passwordError = async (response) => {
  if (typeof response.error === "object") {
    // Initialize an array to store error messages
    const errorMessages = [];

    // Check for each possible attribute and append its messages
    if (response.error.short) {
      errorMessages.push(...response.error.short);
    }
    if (response.error.upper) {
      errorMessages.push(...response.error.upper);
    }
    if (response.error.lower) {
      errorMessages.push(...response.error.lower);
    }
    if (response.error.number) {
      errorMessages.push(...response.error.number);
    }
    if (response.error.special) {
      errorMessages.push(...response.error.special);
    }

    if (errorMessages.length === 0) {
      return response.error;
    }

    // Combine messages into a single string with \n between each
    return errorMessages.join(" ");
  }

  // If it's not a dictionary, return the error as is (string or other type)
  return response.error;
};

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

export const createUserAction = async (formData) => {
  const data = {
    email: formData.get("email"),
    first_name: formData.get("first_name"),
    last_name: formData.get("last_name"),
    password: formData.get("password"),
    c_password: formData.get("c_password"),
  };

  try {
    const response = await createUser(data);

    if (response.error) {
      return { error: response.error };
    };
    
    return { success: response.success };
  } catch (error) {
    console.error(error);
    return { error: error.message || "Failed to create user." };
  };
};