import { apiClient } from "./apiClient";
import { 
  setSessionCookie,
  deleteSessionCookie,
  getUserIdFromSession,
  getUserRoleFromSession,
  getRefreshTokenFromSession
} from "./cookie";


const HTTPS = process.env.HTTPS === 'true';
const API_BASE_URL = HTTPS ? process.env.PUBLIC_API_BASE_HTTPS_URL : process.env.PUBLIC_API_BASE_URL;

export const login = async (data) => {
  const response = await apiClient(`${API_BASE_URL}/login/`, {
    method: "POST",
    body: JSON.stringify(data),
  });

  return response;
};


export const getToken = async (data) => {
  const response = await apiClient(`${API_BASE_URL}/token/`, {
    method: "POST",
    body: JSON.stringify(data),
  });

  return response;
};

export const resendOtp = async (data) => {
  const response = await apiClient(`${API_BASE_URL}/resend-otp/`, {
    method: "POST",
    body: JSON.stringify(data),
  });

  return response;
};


export const logout = async () => {
  const refreshToken = await getRefreshTokenFromSession();

  if (refreshToken) {
    const response = await apiClient(`${API_BASE_URL}/logout/`, {
      method: "POST",
      body: JSON.stringify({ refresh: refreshToken }),
    })

    return response;
  }

  await deleteSessionCookie();
};

export const refreshToken = async () => {
  const refreshToken = await getRefreshTokenFromSession();

  if (!refreshToken) {
    await logout();
    throw new Error("Refresh token not found.");
  };
  
  const response = await apiClient(`${API_BASE_URL}/token/refresh/`, {
    method: "POST",
    body: JSON.stringify({ refresh: refreshToken }),
  });

  if (response.access && response.refresh) {
    const user_id = await getUserIdFromSession();
    const user_role = await getUserRoleFromSession();

    const data = {
      access_token: response.access,
      refresh_token: response.refresh,
      user_role: user_role,
      user_id: user_id
    }

    await setSessionCookie(data);
  };

  return response;
};

export const getUsers = async () => {
  const response = await apiClient(`${API_BASE_URL}/users/`, {
    method: "GET",
  });

  return response;
};