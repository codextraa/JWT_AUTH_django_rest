'use server';

import { signIn } from "next-auth/react"
import { login, getToken, resendOtp, socialOauth} from '@/libs/api';
import { setSessionCookie } from '@/libs/cookie';

export async function loginAction(formData) {
  const email = formData.get('email');
  const password = formData.get('password');

  const credentials = {
    email: email,
    password: password
  };

  try {
    // Make the login request to the backend API
    return await login(credentials);
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

    if (response.access_token && response.refresh_token 
        && response.user_role && response.user_id 
        && response.access_token_expiry) {
        await setSessionCookie(response);
        // Return success response if OTP verification is successful
        return { success: 'OTP verified successfully' };
    } else {
      // Return error if OTP verification fails
      return response;
    }
  } catch (error) {
    // Handle any network or unexpected error
    console.log(error);
    return { error: error.message || 'An error occurred during OTP verification.' };
  };
};

export async function resendOtpAction(user_id) {
  const user = {
    user_id: user_id
  };

  try {
    // Make the login request to the backend API
    return await resendOtp(user);
  } catch (error) {
    // Handle any network or unexpected error
    console.log(error);
    return { error: error.message || 'An error occurred during login.' };
  };
};

export async function socialLoginAction(provider, accessToken) {
  console.log('entered socialLoginAction')
  try {
    const auth_data = {
      provider: provider,
      token: accessToken
    };
    const response = await socialOauth(auth_data)
    if (response.access_token && response.refresh_token 
      && response.user_role && response.user_id 
      && response.access_token_expiry) {
      await setSessionCookie(response);
      // Return success response if OTP verification is successful
      return { success: 'OTP verified successfully' };
    } else {
      return { error: result.error || "Backend authentication failed" }
    };
  } catch (error) {
    console.error(error)
    return { error: error.message || "An error occurred during login." }
  };
};