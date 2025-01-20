// import { redirect } from "next/dist/server/api-utils";
import { ApiClient } from "./apiClient";
import { 
  getRefreshTokenFromSession,
  deleteSessionCookie
} from "./cookie";


const HTTPS = process.env.HTTPS === 'true';
const API_URL = HTTPS? process.env.API_BASE_HTTPS_URL : process.env.API_BASE_URL;
const apiClient = new ApiClient(API_URL);

// API functions
export const login = async (data) => {
  return apiClient.post('/login/', data);
};

export const getToken = async (data) => {
  return apiClient.post('/token/', data);
};

export const resendOtp = async (data) => {
  return apiClient.post('/resend-otp/', data);
};

export const refreshToken = async (refreshToken) => {
  return await apiClient.post('/token/refresh/', { refresh: refreshToken });
};

export const logout = async () => {
  const refreshToken = await getRefreshTokenFromSession();

  if (refreshToken) {
    await apiClient.post('/logout/', { refresh: refreshToken });
  }

  await deleteSessionCookie();
  // redirect('/login');
};

export const getUsers = async () => {
  return apiClient.get('/users/');
};