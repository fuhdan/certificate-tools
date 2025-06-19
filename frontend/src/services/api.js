import AxiosInterceptor from '../hooks/axiosInstance.jsx';

class ApiService {
    constructor() {
        this.axiosInstance = new AxiosInterceptor({
            tokenUsername: import.meta.env.VITE_REACT_APP_API_USER,
            tokenPassword: import.meta.env.VITE_REACT_APP_API_PASSWORD,
            baseURL: import.meta.env.VITE_REACT_APP_API_URL,
        });
        
        // Debug logging
        console.log('API Service initialized with baseURL:', import.meta.env.VITE_REACT_APP_API_URL);
    }

    // File upload and processing
    async uploadFile(file) {
        try {
            const formData = new FormData();
            formData.append('file', file);

            const response = await this.axiosInstance.post('/upload', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            });

            return {
                success: true,
                data: response.data,
                message: 'File processed successfully'
            };
        } catch (error) {
            return this._handleError(error, 'Failed to process file');
        }
    }

    // Health check
    async healthCheck() {
        try {
            const response = await this.axiosInstance.get('/health');
            return {
                success: true,
                data: response.data,
                status: response.data.status
            };
        } catch (error) {
            return this._handleError(error, 'Health check failed');
        }
    }

    // Private error handler
    _handleError(error, defaultMessage) {
        console.error('API Error:', error);
        
        const errorMessage = error.response?.data?.detail || 
                           error.response?.data?.message || 
                           error.message || 
                           defaultMessage;

        return {
            success: false,
            error: errorMessage,
            statusCode: error.response?.status,
            data: null
        };
    }
}

// Create singleton instance
const apiService = new ApiService();

export default apiService;