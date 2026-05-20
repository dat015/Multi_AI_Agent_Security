import { useQuery } from '@tanstack/react-query';
import { getUsers } from '../api/workFlow';

export const UsersPage = () => {
  const { data: users, isLoading, isError } = useQuery({
    queryKey: ['users'],
    queryFn: getUsers,
  });

  if (isLoading) return <div className="p-4">Loading users...</div>;
  if (isError) return <div className="p-4 text-red-500">Failed to load users.</div>;

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Users List</h1>
      <ul className="space-y-2">
        {users?.map((user) => (
          <li key={user.id} className="p-4 bg-white shadow rounded-lg border border-gray-200">
            <p className="font-semibold">{user.name}</p>
            <p className="text-gray-600 text-sm">{user.email}</p>
          </li>
        ))}
      </ul>
    </div>
  );
};