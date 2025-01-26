'use client';

import { signIn, signOut } from "next-auth/react";
import { useState } from "react";
import { useFormStatus } from 'react-dom';
import { logoutAction } from "@/actions/authActions";
import baseStyles from './Button.module.css';
import socialStyles from './SocialLoginButton.module.css';

export const LoginButton = ({ disabled }) => {
  const { pending } = useFormStatus();

  return (
    <button 
    type="submit" 
    disabled={disabled || pending} 
    className={baseStyles.loginButton}
    >
      {pending ? 'Logging in...' : disabled ? 'Login' : 'Login'}
    </button>
  );
};

export const OtpVerifyButton = () => {
  const { pending } = useFormStatus();

  return (
    <button type="submit" disabled={pending} className={baseStyles.otpVerifyButton}>
      {pending ? 'Verifying...' : 'Verify OTP'}
    </button>
  );
};

export const ResendOtpButton = ({ onClick, disabled, timer }) => {
  const { pending } = useFormStatus();

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || pending}
      className={baseStyles.resendOtpButton}
    >
      {pending ? 'Resending...' : disabled ? `Resend OTP (${timer}s)` : 'Resend OTP'}
    </button>
  );
};

function SocialLoginButton({ provider, isDisabled, icon }) {
  const [isLoading, setIsLoading] = useState(false)
  const disabled = isDisabled.isDisabled

  const handleClick = async () => {
    setIsLoading(true)
    try {
      await signIn(provider, { redirectTo: "/jwt/login" })
    } catch (error) {
      console.error("Error during social login:", error)
    }
    setIsLoading(false)
  }

  return (
    <button
    type="button"
    disabled={disabled || isLoading}
    className={`${socialStyles.button} ${socialStyles[provider.toLowerCase()]}`}
    onClick={handleClick}
    >
      {/* {console.log(icon)} Find out what this is*/} 
      {icon}
      <span>{isLoading ? `Logging in with ${provider}...` : disabled ? `Login with ${provider}` : `Login with ${provider}`}</span>
    </button>
  );
};

export const LogOutButton = () => {
  const [isLoading, setIsLoading] = useState(false)

  const handleClick = async () => {
    setIsLoading(true)
    try {
      await logoutAction();
      await signOut();
    } catch (error) {
      console.error("Error during social login:", error)
    }
    setIsLoading(false)
  };

  return (
    <button
      type="submit"
      disabled={isLoading}
      className={baseStyles.loginButton}
      onClick={handleClick}
    >
      <span>{isLoading ? `Logging out...` : `Logout`}</span>
    </button>
  );
};


export function GoogleLoginButton( isDisabled ) {
  return ( <SocialLoginButton 
    provider="Google" 
    isDisabled={isDisabled}
    icon={<i className="fab fa-google"></i>}
  />
  );
};

export function FacebookLoginButton( isDisabled ) {
  return (
    <SocialLoginButton 
    provider="Facebook" 
    isDisabled={isDisabled}
    icon={<i className="fab fa-facebook-f"></i>} 
  />
  );
};

export function GitHubLoginButton( isDisabled ) {
  return ( <SocialLoginButton 
    provider="GitHub" 
    isDisabled={isDisabled}
    icon={<i className="fab fa-github"></i>} 
  />
  );
};


// export function InstagramLoginButton() {
//   return (
//     <SocialLoginButton 
//     provider="Instagram" 
//     icon={<i className="fab fa-instagram"></i>} 
//   />
//   );
// };

// export function TwitterLoginButton() {
//   return ( <SocialLoginButton 
//   provider="Twitter" 
//   icon={<i className="fab fa-twitter"></i>} 
//   />
//   );
// };

// export function LinkedInLoginButton() {
//   return (
//     <SocialLoginButton 
//     provider="LinkedIn" 
//     icon={<i className="fab fa-linkedin-in"></i>} 
//   />
//   );
// };