import { getUsers } from "@/libs/api";
import { LogOutButton } from "@/components/Buttons/Button";


export default async function ProfilePage() {
  const users = await getUsers();

  return (
    <div>
      {JSON.stringify(users)}
      <h1>Profile Page</h1>
      <LogOutButton />
    </div>
  );
}