import axios from 'axios';

class AxiosInterceptor {
    constructor({ tokenUsername, tokenPassword, baseURL }) {
        this.axiosInstance = axios.create({
            baseURL: baseURL,
            timeout: 10000,
        });

        // Request interceptor
        this.axiosInstance.interceptors.request.use(
            (config) => {
                // Add basic auth if credentials are provided
                if (tokenUsername && tokenPassword) {
                    const token = btoa(`${tokenUsername}:${tokenPassword}`);
                    config.headers.Authorization = `Basic ${token}`;
                }
                
                console.debug('Request sent:', config);
                return config;
            },
            (error) => {
                console.error('Request error:', error);
                return Promise.reject(error);
            }
        );

        // Response interceptor
        this.axiosInstance.interceptors.response.use(
            (response) => {
                console.debug('Response received:', response);
                return response;
            },
            (error) => {
                console.error('Response error:', error);
                return Promise.reject(error);
            }
        );
    }

    get(url, config) {
        return this.axiosInstance.get(url, config);
    }

    post(url, data, config) {
        return this.axiosInstance.post(url, data, config);
    }

    patch(url, data, config) {
        return this.axiosInstance.patch(url, data, config);
    }

    delete(url, config) {
        return this.axiosInstance.delete(url, config);
    }
}

export default AxiosInterceptor;