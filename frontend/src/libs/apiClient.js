import axios from 'axios';
import { 
  setSessionCookie, 
  getUserIdFromSession, 
  getUserRoleFromSession, 
  getAccessTokenFromSession, 
  getRefreshTokenFromSession 
} from './cookie';
import { refreshToken } from './api';

// Create an Axios instance
export const apiClient = axios.create({
  baseURL: process.env.PUBLIC_API_BASE_URL,
  withCredentials: true, // Include credentials (cookies) in requests
});

// Axios Request Interceptor to attach access token to Authorization header
apiClient.interceptors.request.use(
  (config) => {
    const accessToken = getAccessTokenFromSession(); // Use cookies() API to get the access token
    if (accessToken) {
      config.headers['Authorization'] = `Bearer ${accessToken}`; // Attach the token
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Axios Response Interceptor to handle token expiration and refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response && error.response.status === 401) {
      try {
        // Get user_id and user_role from the session cookie
        const userId = getUserIdFromSession();
        const userRole = getUserRoleFromSession();

        // Retrieve the refresh token from the session cookie
        const refreshTokenValue = getRefreshTokenFromSession();

        if (!refreshTokenValue) {
          throw new Error('Refresh token not found');
        }

        // Call the refreshToken API to get new tokens
        const refreshResponse = await refreshToken(refreshTokenValue);

        // Extract new tokens from the response
        const { access, refresh } = refreshResponse.data;

        // Create new session data, retaining user_id and user_role
        const newSessionData = {
          access_token: access,
          refresh_token: refresh,
          user_id: userId,
          user_role: userRole,
        };

        // Set the updated session cookie
        setSessionCookie(newSessionData);

        // Retry the original request with the new access token
        error.config.headers['Authorization'] = `Bearer ${access}`;
        return axios.request(error.config); // Retry the failed request
      } catch (refreshError) {
        console.error('Error refreshing token:', refreshError);
        return Promise.reject(refreshError); // Handle any errors during the refresh process
      }
    }

    return Promise.reject(error); // Pass other errors through
  }
);