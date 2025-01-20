import { getAccessTokenFromSession } from "./cookie";


export class ApiClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
  };

  async handleErrors(response) {
    if (response.ok) {
      if (response.status === 204) {
        return null; // No content
      }
      return await response.json(); // Success case
    };

    if (response.status >= 400) {
      if (response.status === 401) {
        return { error: "Unauthorized. Please refresh the page. If this persists login again" };
      }

      if (response.status === 429) {
        const error_response = await response.json();
        const error_message = error_response.errors;

        try{
          const match = error_message.match(/(\d+) second(s)?/);
          return { error: `Validation already sent. Please try again in ${match[1]} seconds.` };
        } catch (error) {
          return { error: `Validation already sent. Please try again.` };
        };
      };

      const errorData = await response.json();

      if (errorData.errors) {
        // Return error if present in the response
        return { error: errorData.errors };
      };

      return { error: `Something went wrong. Please try again.` };
    };

    if (response.status >= 500) {
      return { errors: "Server error" }; // Server-side error
    };

    throw new Error("Unexpected error occurred.");
  };

  async request(endpoint, method, data = null, additionalOptions = {}, isMultipart = false) {
    const accessToken = await getAccessTokenFromSession();
    const url = `${this.baseURL}${endpoint}`;

    let options = {
      method,
      headers: {
        "Accept": "application/json",
        ...(accessToken && { Authorization: `Bearer ${accessToken}` }),
      },
      credentials: "include",
      ...additionalOptions,
    };

    if (isMultipart && data instanceof FormData) {
      // For multipart/form-data
      // delete options.headers["Content-Type"];
      options.body = data;
    } else if (data) {
      // For application/json
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(data);
    }

    try {
      const response = await fetch(url, options);
      return await this.handleErrors(response);
    } catch (error) {
      console.error("Fetch error:", error);
      throw error;
    };
  };

  async get(endpoint, additionalOptions = {}) {
    return await this.request(endpoint, "GET", null, additionalOptions);
  };

  async post(endpoint, data, additionalOptions = {}, isMultipart = false) {
    return await this.request(endpoint, "POST", data, additionalOptions, isMultipart);
  };

  async patch(endpoint, data, additionalOptions = {}, isMultipart = false) {
    return await this.request(endpoint, "PATCH", data, additionalOptions, isMultipart);
  };

  async put(endpoint, data, additionalOptions = {}, isMultipart = false) {
    return await this.request(endpoint, "PUT", data, additionalOptions, isMultipart);
  };

  async delete(endpoint, data = null, additionalOptions = {}) {
    return await this.request(endpoint, "DELETE", data, additionalOptions);
  };
};
