import { getAccessTokenFromSession } from "./cookie";
import { refreshToken } from "./api";

export const apiClient = async (url, options = {}) => {
  const accessToken = await getAccessTokenFromSession();

  options.headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    ...options.headers,
  };

  if (accessToken) {
    options.headers = {
      ...options.headers,
      Authorization: `Bearer ${accessToken}`,
    };
  }

  options.credentials = "include";

  try {
    const response = await fetch(url, options);

    console.log("apiClient", response);
    if (!response.ok) {
      if (response.status === 401) {
        await refreshToken();
        return apiClient(url, options);
      }
      if (response.status >= 500) {
        return { errors: "Server error" };
      }
      console.error("Fetch error:", response);
      return response.json();
    }

    if (response.status === 204) {
      return null;
    }

    return response.json();
  } catch (error) {
    console.error("Fetch error:", error);
    throw error;
  };
};