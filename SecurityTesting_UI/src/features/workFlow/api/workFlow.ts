import { apiClient } from '../../../lib/axios';

export interface User {
  id: string;
  name: string;
  email: string;
}

export const getUsers = async (): Promise<User[]> => {
  return apiClient.get('/users');
};