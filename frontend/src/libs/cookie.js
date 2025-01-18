import { cookies } from 'next/headers';
import { encrypt, decrypt, validateSessionData } from './session';
import { BASE_ROUTE } from '@/route';

export const setSessionCookie = async (data) => {
  try {
    // Validate the incoming session data
    const sessionData = validateSessionData(data); // Sanitize and validate data
    if (!sessionData) {
      throw new Error('Invalid session data.');
    };

    // Encrypt the session data
    const encryptedSessionData = encrypt(sessionData);

    // Create a secure cookie
    // Set the secure cookie using Next.js cookies API
    const cookieStore = await cookies();
    cookieStore.set('session', encryptedSessionData, {
      httpOnly: true,
      secure: process.env.HTTPS, // Secure in production
      maxAge: 60 * 60 * 24, // One day in seconds
      path: BASE_ROUTE, // Dynamic path
      sameSite: 'lax', // Helps prevent CSRF attacks
    });

    return { success: 'Successfully set cookie!' };
  } catch (error) {
    console.error('Error setting cookie:', error);
    throw new Error('Failed to set session cookie.');
  };
};

export const getUserIdFromSession = async () => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('session'); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  try {
    const decryptedData = decrypt(sessionCookie.value); // Decrypt the session data
    return decryptedData?.user_id || null; // Return user_id if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};

export const getUserRoleFromSession = async () => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('session'); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  try {
    const decryptedData = decrypt(sessionCookie.value); // Decrypt the session data
    return decryptedData?.user_role || null; // Return user_role if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};

export const getAccessTokenFromSession = async () =>  {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('session'); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  try {
    const decryptedData = decrypt(sessionCookie.value); // Decrypt the session data
    return decryptedData?.access_token || null; // Return access_token if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};

export const getRefreshTokenFromSession = async () =>  {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('session'); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  try {
    const decryptedData = decrypt(sessionCookie.value); // Decrypt the session data
    return decryptedData?.refresh_token || null; // Return refresh_token if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};

export const deleteSessionCookie = async () => {
  const cookieStore = await cookies();

  if (cookieStore.has('session')) {
    cookieStore.delete('session');
  };
};