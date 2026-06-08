import { ApiClient } from "./apiClient";
// import { getRefreshTokenFromSession } from "./cookie";

const HTTPS = process.env.HTTPS === "true";
const API_URL = HTTPS
  ? process.env.API_BASE_HTTPS_OLD_URL
  : process.env.API_BASE_URL;
const apiClient = new ApiClient(API_URL || "");

// API functions
export const getCSRFToken = async (): Promise<any> => {
  return apiClient.get("/get-csrf-token/");
};

export const refreshToken = async (refreshToken: string): Promise<any> => {
  return await apiClient.post("/token/refresh/", { refresh: refreshToken });
};