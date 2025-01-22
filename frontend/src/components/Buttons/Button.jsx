'use client';

import { useFormStatus } from 'react-dom';
import baseStyles from './Button.module.css';
import socialStyles from './SocialLoginButton.module.css';
import {
  googleLoginAction,
  facebookLoginAction,
  twitterLoginAction,
  githubLoginAction,
  instagramLoginAction,
  linkedinLoginAction
} from '@/actions/authActions';

export const LoginButton = () => {
  const { pending } = useFormStatus();

  return (
    <button type="submit" name='action' value='login' disabled={pending} className={baseStyles.loginButton}>
      {pending ? 'Logging in...' : 'Login'}
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

export function SocialLoginButton({ provider, icon, action }) {
  const { pending } = useFormStatus()

  return (
    <button type="submit" disabled={pending} className={`${socialStyles.button} ${socialStyles[provider]}`} formAction={action}>
      {icon}
      <span>{pending ? `Logging in with ${provider}...` : `Login with ${provider}`}</span>
    </button>
  )
};

export function GoogleLoginButton() {
  return <SocialLoginButton 
  provider="Google" 
  icon={<i className="fab fa-google"></i>}
  action={googleLoginAction}/>
};

export function FacebookLoginButton() {
  return (
    <SocialLoginButton 
    provider="Facebook" 
    icon={<i className="fab fa-facebook-f"></i>} 
    action={facebookLoginAction} />
  )
};

export function InstagramLoginButton() {
  return (
    <SocialLoginButton 
    provider="Instagram" 
    icon={<i className="fab fa-instagram"></i>} 
    action={instagramLoginAction} />
  )
};

export function TwitterLoginButton() {
  return <SocialLoginButton 
  provider="Twitter" 
  icon={<i className="fab fa-twitter"></i>} 
  action={twitterLoginAction} 
  />
};

export function LinkedInLoginButton() {
  return (
    <SocialLoginButton 
    provider="LinkedIn" 
    icon={<i className="fab fa-linkedin-in"></i>} 
    action={linkedinLoginAction} />
  )
};

export function GitHubLoginButton() {
  return <SocialLoginButton 
  provider="GitHub" 
  icon={<i className="fab fa-github"></i>} 
  action={githubLoginAction} />
};
