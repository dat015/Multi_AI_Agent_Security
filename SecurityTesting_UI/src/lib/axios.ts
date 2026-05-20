import axios from 'axios';
// Lấy base URL từ biến môi trường
const API_URL = import.meta.env.VITE_API_URL || 'https://api.example.com';

export const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor cho Request: Gắn token nếu có
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token'); // Hoặc lấy từ store
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Interceptor cho Response: Xử lý lỗi chung (VD: hết hạn token)
apiClient.interceptors.response.use(
  (response) => response.data, // Chỉ lấy data, bỏ qua vỏ axios
  (error) => {
    if (error.response?.status === 401) {
      // Logic xử lý logout hoặc refresh token ở đây
      console.error('Unauthorized, please login again.');
    }
    return Promise.reject(error);
  }
);