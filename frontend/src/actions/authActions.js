'use server';

import { login, getToken } from '@/libs/api';
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
    const response = await login(credentials);
    console.log(response);

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

  const otp = {
    otp: otp_data
  };

  try {
    // Call the backend API to verify OTP
    const response = await getToken(otp);

    console.log('response', response);
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
        }
        console.log('response data', data);
        await setSessionCookie(data);
      };

    // Return success response if OTP verification is successful
    return { success: 'OTP verified successfully' };
  } catch (error) {
    // Handle any network or unexpected error
    return { error: error.message || 'An error occurred during OTP verification.' };
  };
};