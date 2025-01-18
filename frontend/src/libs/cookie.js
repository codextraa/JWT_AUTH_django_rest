import { serialize, parse } from 'cookie';
import { encrypt, decrypt } from '@/app/lib/session';
import { validateSessionData } from '@/app/lib/session'; // Custom validation logic
import { BASE_ROUTE } from '@/route';

export default function setSessionCookie(req, res) {
  try {
    // Validate the incoming session data
    const sessionData = validateSessionData(req.body); // Sanitize and validate data
    if (!sessionData) {
      return res.status(400).json({ message: 'Invalid session data' });
    };

    // Encrypt the session data
    const encryptedSessionData = encrypt(sessionData);

    // Create a secure cookie
    const cookie = serialize('session', encryptedSessionData, {
      httpOnly: true,
      secure: process.env.HTTPS,
      maxAge: 60 * 60 * 24, // One day
      path: `${BASE_ROUTE}`,
      sameSite: 'Lax', // Prevent CSRF attacks
    });

    // Set the cookie in the response
    res.setHeader('Set-Cookie', cookie);
    return res.status(200).json({ message: 'Successfully set cookie!' });
  } catch (error) {
    console.error('Error setting cookie:', error);
    return res.status(500).json({ message: 'An error occurred' });
  };
};

export function getUserIdFromSession(req) {
  const cookies = parse(req.headers.cookie || ''); // Parse cookies
  const sessionCookie = cookies.session; // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  try {
    const decryptedData = decrypt(sessionCookie); // Decrypt the session data
    if (decryptedData && decryptedData.user_id) {
      return decryptedData.user_id; // Return the user_id
    };
    return null; // No user_id found in decrypted data
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  }
};

export function getUserRoleFromSession(req) {
  const cookies = parse(req.headers.cookie || '');
  const sessionCookie = cookies.session;

  if (!sessionCookie) {
    return null;
  };

  try {
    const decryptedData = decrypt(sessionCookie);
    if (decryptedData && decryptedData.user_role) {
      return decryptedData.user_role; // Return the user_role
    };
    return null; // No user_role found in decrypted data
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null;
  };
};

export function getAccessTokenFromSession(req) {
  const cookies = parse(req.headers.cookie || '');
  const sessionCookie = cookies.session;

  if (!sessionCookie) {
    return null;
  };

  try {
    const decryptedData = decrypt(sessionCookie);
    if (decryptedData && decryptedData.access_token) {
      return decryptedData.access_token; // Return the access_token
    };
    return null; // No access_token found in decrypted data
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null;
  };
};

export function getRefreshTokenFromSession(req) {
  const cookies = parse(req.headers.cookie || '');
  const sessionCookie = cookies.session;

  if (!sessionCookie) {
    return null;
  };

  try {
    const decryptedData = decrypt(sessionCookie);
    if (decryptedData && decryptedData.refresh_token) {
      return decryptedData.refresh_token; // Return the refresh_token
    };
    return null; // No refresh_token found in decrypted data
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null;
  };
};