import Link from "next/link";

export default function Page() {
  return (
    <div className="min-h-screen bg-gray-50 text-gray-800 flex flex-col items-center justify-center p-6 sm:p-12">
      <div className="max-w-3xl w-full bg-white border border-gray-100 rounded-3xl shadow-xl p-8 sm:p-12 space-y-8">

        <div className="text-center space-y-3">
          <h1 className="text-4xl sm:text-5xl font-black tracking-tight text-[#1e2a6e]">
            Welcome to JWT-AUTH
          </h1>
          <div className="h-1.5 w-20 bg-[#1e2a6e] rounded-full mx-auto" />
        </div>

        <div className="space-y-6 text-base sm:text-lg leading-relaxed text-gray-600">
          <p>
            A full-stack web application built with <strong className="text-black font-semibold">NextJS</strong> for the
            frontend and <strong className="text-black font-semibold">Django</strong> for the backend, utilizing{" "}
            <strong className="text-black font-semibold">REST</strong> APIs and a <strong className="text-black font-semibold">PostgreSQL</strong> database.
          </p>

          <p className="bg-gray-50 border-l-4 border-[#1e2a6e] p-4 rounded-r-2xl text-gray-700">
            This project demonstrates a secure authentication system using{" "}
            <strong className="text-[#1e2a6e] font-semibold">JSON Web Tokens (JWT)</strong>, featuring OTP-based login, email
            verification-based registration, email and phone verification, password
            reset, and social media login integration. 
          </p>

          <p>
            The flow starts with a login page where users enter their email and password. Upon successful
            authentication, an OTP is sent to the user's email for verification.
            After verifying the OTP, a secure session is established, and users receive a
            session ID and CSRF token for accessing protected routes. Users can freely
            edit their profiles on the <strong className="text-black font-semibold">Profile</strong> page, where profile images are seamlessly retrieved from social providers or fallback to a crisp default image.
          </p>

          <div className="bg-amber-50 border border-amber-200 p-5 rounded-2xl">
            <p className="text-amber-900 text-sm sm:text-base">
              <strong className="text-amber-800 font-bold">Superusers</strong> and{" "}
              <strong className="text-amber-800 font-bold">Admins</strong> have elevated
              privileges allowing them to access the <strong className="font-semibold">Admin Dashboard</strong> to{" "}
              <span className="italic">activate, deactivate, edit, or delete</span> users according to their respective roles.
            </p>
          </div>
        </div>

        <div className="pt-6 border-t border-gray-100 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-sm text-gray-500">
            Want to explore the codebase?
          </p>
          <a
            href="https://github.com/codextraa/JWT_AUTH_django_rest"
            target="_blank"
            rel="noopener noreferrer"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 bg-[#2d2d2d] hover:bg-[#1a1a1a] text-white font-semibold px-6 py-3 rounded-full transition-all transform hover:-translate-y-0.5 shadow-md"
          >

            <svg className="w-5 h-5 fill-current" viewBox="0 0 24 24">
              <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z" />
            </svg>
            Visit GitHub Repository
          </a>
        </div>

      </div>
    </div>
  );
}