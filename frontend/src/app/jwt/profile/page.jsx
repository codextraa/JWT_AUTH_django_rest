import { getUsers } from "@/libs/api";
// import { getAccessTokenExpiryFromSession } from "@/libs/cookie";

export default async function ProfilePage() {
  // const expired = await getAccessTokenExpiryFromSession();

  // // Function to wait for a specified amount of time in milliseconds
  // const delay = (time) => new Promise(resolve => setTimeout(resolve, time));

  // // If token has expired, wait for 5 seconds before calling getUsers
  // if (!expired) {
  //   await delay(5000); // Wait for 5 seconds
  // }

  // After the delay (or immediately if not expired), fetch users
  const users = await getUsers();

  return (
    <div>
      {JSON.stringify(users)}
      <h1>Profile Page</h1>
    </div>
  );
}