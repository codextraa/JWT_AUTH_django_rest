import { ApiClient } from "./apiClient";
// import { getRefreshTokenFromSession } from "./cookie";
import { CSRFTokenResponse, SessionResponse } from "@/types/types";

const HTTPS = process.env.HTTPS === "true";
const API_URL_OLD = HTTPS
  ? process.env.API_BASE_HTTPS_OLD_URL
  : process.env.API_BASE_URL;
const apiClientOld = new ApiClient(API_URL_OLD || "");

// const API_URL = HTTPS
//   ? process.env.API_BASE_HTTPS_URL
//   : process.env.API_BASE_URL;
// const apiClient = new ApiClient(API_URL || "");

// API functions
export const getCSRFToken = async (): Promise<CSRFTokenResponse> => {
  return apiClientOld.get("/get-csrf-token/");
};

export const refreshToken = async (data: {
  refresh: string;
}): Promise<SessionResponse> => {
  return await apiClientOld.post("/token/refresh/", data);
};
