'use server';

import { login, getToken, resendOtp, googleLogin} from '@/libs/api';
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

export async function googleLoginAction() {
  try {
    const response = await googleLogin();
    console.log('response', response);
    return response;
  } catch (error) {
    console.log(error);
    return { error: error.message || 'An error occurred during login.' };
  };
};

export async function facebookLoginAction() {
  // Implement Facebook login logic
  console.log("Facebook login action")
  return { success: "Facebook login successful" }
};

export async function instagramLoginAction() {
  // Implement Instagram login logic
  console.log("Instagram login action")
  return { success: "Instagram login successful" }
};

export async function linkedinLoginAction() {
  // Implement LinkedIn login logic
  console.log("LinkedIn login action")
  return { success: "LinkedIn login successful" }
};

export async function githubLoginAction() {
  // Implement GitHub login logic
  console.log("GitHub login action")
  return { success: "GitHub login successful" }
};

export async function twitterLoginAction() {
  // Implement Twitter login logic
  console.log("Twitter login action")
  return { success: "Twitter login successful" }
};