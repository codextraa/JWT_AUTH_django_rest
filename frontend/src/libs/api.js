import { apiClient } from "./apiClient";
import { 
  setSessionCookie,
  deleteSessionCookie,
  getUserIdFromSession,
  getUserRoleFromSession,
  getRefreshTokenFromSession
} from "./cookie";


const HTTPS = process.env.HTTPS;
const API_BASE_URL = HTTPS ? process.env.PUBLIC_API_BASE_HTTPS_URL : process.env.PUBLIC_API_BASE_URL;

export const login = async (credentials) => {
  const response = await apiClient(`${API_BASE_URL}/login/`, {
    method: "POST",
    body: JSON.stringify(credentials),
  });

  return response;
};


export const getToken = async (otp) => {
  const response = await apiClient(`${API_BASE_URL}/token/`, {
    method: "POST",
    body: JSON.stringify(otp),
  });

  if (response.access && response.refresh && response.user_role ** response.user_id) {
    data = {
      access_token: response.access,
      refresh_token: response.refresh,
      user_role: response.user_role,
      user_id: response.user_id
    }

    await setSessionCookie(data);
  };

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
  
  const response = await fetchClient(`${API_BASE_URL}/token/refresh/`, {
    method: "POST",
    body: JSON.stringify({ refresh: refreshToken }),
  });

  if (response.access && response.refresh) {
    const user_id = await getUserIdFromSession();
    const user_role = await getUserRoleFromSession();

    data = {
      access_token: response.access,
      refresh_token: response.refresh,
      user_role: user_role,
      user_id: user_id
    }

    await setSessionCookie(data);
  };

  return response;
};