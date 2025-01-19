'use server';

import { login, getToken, resendOtp } from '@/libs/api';
import { setSessionCookie } from '@/libs/cookie';
import { revalidatePath } from 'next/cache';
import { BASE_ROUTE } from '@/route';

export async function loginAction(formData) {
  const email = formData.get('email');
  const password = formData.get('password');

  const credentials = {
    email: email,
    password: password
  };

  try {
    // Make the login request to the backend API
    const response = await login(credentials);

    if (response.status_code === 429) {
      const error_message = response.errors;
      const match = error_message.match(/(\d+) seconds/);

      return { error: `OTP already sent. Please try again in ${match[1]} seconds.` };
    }

    if (response.errors) {
      // Return error if present in the response
      return { error: response.errors };
    };

    // Return success response if login is successful
    return response;
  } catch (error) {
    // Handle any network or unexpected error
    console.log(error);
    return { error: error.message || 'An error occurred during login.' };
  };
};

export async function verifyOtpAction(formData) {
  const otp_data = formData.get('otp');
  const user_id = formData.get('user_id');

  const otp = {
    user_id: user_id,
    otp: otp_data
  };

  try {
    // Call the backend API to verify OTP
    const response = await getToken(otp);

    // Check if the response contains an error
    if (response.errors) {
      // Return error if present in the response
      return { error: response.errors };
    };

    console.log(response);

    if (response.access && response.refresh && response.user_role && response.user_id) {
        const data = {
          access_token: response.access,
          refresh_token: response.refresh,
          user_role: response.user_role,
          user_id: response.user_id
        };

        await setSessionCookie(data);
      };

    // Return success response if OTP verification is successful
    return { success: 'OTP verified successfully' };
  } catch (error) {
    // Handle any network or unexpected error
    console.log(error);
    return { error: error.message || 'An error occurred during OTP verification.' };
  };
};

// {"success": "Email sent", "otp": True, "user_id": user_id}
export async function resendOtpAction(user_id) {
  const user = {
    user_id: user_id
  };

  try {
    // Make the login request to the backend API
    const response = await resendOtp(user);

    if (response.status_code === 429) {
      const error_message = response.errors;
      const match = error_message.match(/(\d+) seconds/);

      return { error: `OTP already sent. Please try again in ${match[1]} seconds.` };
    }

    if (response.errors) {
      // Return error if present in the response
      return { error: response.errors };
    };

    // Return success response if login is successful
    return response;
  } catch (error) {
    // Handle any network or unexpected error
    console.log(error);
    return { error: error.message || 'An error occurred during login.' };
  };
};
  