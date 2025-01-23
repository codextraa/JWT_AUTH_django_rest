export const BASE_ROUTE = '/jwt'
export const DEFAULT_LOGIN_REDIRECT = `${BASE_ROUTE}/profile`;

export const authRoutes = [
  `${BASE_ROUTE}/login`,
  `${BASE_ROUTE}/otp`,
  `${BASE_ROUTE}/register`,
]

export const apiRoute = `/api`;

export const publicRoutes = [
  `${BASE_ROUTE}`,
]
