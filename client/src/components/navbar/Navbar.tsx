"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import Button from "@/components/buttons/Buttons";
// import { logoutAction } from "@/actions/authActions";
import { NavbarProps } from "@/types/types";

//! navbar admin superuser review below
export default function Navbar({ isLoggedIn }: NavbarProps) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  const handleLogout = async () => {
    setLoading(true);
    // await logoutAction();
    router.push("/auth/login");
    router.refresh();
    setLoading(false);
  };

  return (
    <nav className="w-full bg-gray-200 px-6 py-4 flex items-center justify-between">
      <Link
        href="/"
        className="text-black font-bold text-lg hover:opacity-80 transition-opacity"
      >
        Auth
      </Link>

      <div className="flex items-center gap-6">
        {isLoggedIn ? (
          <>
            <Link
              href="/profile"
              className="text-black text-sm font-medium underline hover:opacity-70 transition-opacity"
            >
              Profile
            </Link>
            <Link
              href="/"
              className="text-black text-sm font-medium hover:opacity-70 transition-opacity"
            >
              Dashboard
            </Link>
            {/* Admin and superuser can only access dashboard */}
            <Button variant="primary" onClick={handleLogout} disabled={loading}>
              {loading ? "Logging out..." : "Log Out"}
            </Button>
          </>
        ) : (
          <>
            <Link
              href="/auth/register"
              className="text-black text-sm font-medium hover:opacity-70 transition-opacity"
            >
              Register
            </Link>
            <Button
              variant="primary"
              onClick={() => router.push("/auth/login")}
            >
              Login
            </Button>
          </>
        )}
      </div>
    </nav>
  );
}
