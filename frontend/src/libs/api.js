import { apiClient } from "./apiClient";
import { 
  setSessionCookie,
  deleteSessionCookie,
  getRefreshTokenFromSession
} from "./cookie";


const API_BASE_URL = process.env.PUBLIC_API_BASE_URL;

export const login = async (email, password) => {
  const response = apiClient.post(
    `${API_BASE_URL}/login`, 
    { 
      email, 
      password 
    }
  );

  return response;
};

export const getToken = async (otp) => {
  const response = apiClient.post(
    `${API_BASE_URL}/token`, 
    { 
      otp 
    }
  );

  await setSessionCookie(response.data);

  return response;
};

export const refreshToken = async (refreshToken) => {
  const response = apiClient.post(
    `${API_BASE_URL}/token/refresh`, 
    { 
      refreshToken 
    }
  );

  return response;
};

export const logout = async () => {
  const refreshToken = await getRefreshTokenFromSession();
  const response = await apiClient.post(
    `${API_BASE_URL}/logout`, 
    {
      refreshToken
    }
  )

  await deleteSessionCookie();

  return response;
};