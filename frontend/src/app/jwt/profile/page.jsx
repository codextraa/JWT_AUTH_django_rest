import { getUsers } from "@/libs/api";

export default async function ProfilePage() {
  const users = await getUsers();

  return (
    <div>
      <h1>Profile Page</h1>
    </div>
  );
}