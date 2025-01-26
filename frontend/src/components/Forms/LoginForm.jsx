'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { loginAction, recaptchaVerifyAction } from '@/actions/authActions';
import { BASE_ROUTE } from '@/route';
import { encrypt } from '@/libs/session';
import styles from './LoginForm.module.css';
import {
  LoginButton,
  GoogleLoginButton,
  FacebookLoginButton,
  // InstagramLoginButton,
  // TwitterLoginButton,
  // LinkedInLoginButton,
  GitHubLoginButton,
} from '../Buttons/Button';

export default function LoginForm() {
  const router = useRouter();
  const [otp, setOtp] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [isRecaptchaVerified, setIsRecaptchaVerified] = useState(false);

  useEffect(() => {
    const otpRequired = sessionStorage.getItem('otpRequired');
    const otpExpiry = sessionStorage.getItem('otpExpiry');

    if (!otpRequired || Date.now() > parseInt(otpExpiry, 10)) {
      sessionStorage.removeItem('otpRequired');
      sessionStorage.removeItem('otpExpiry');
      setOtp(false);
    } else {
      setOtp(true);
    }
  }, []);

  useEffect(() => {
    // Dynamically load reCAPTCHA script
    const script = document.createElement('script');
    script.src = 'https://www.google.com/recaptcha/api.js';
    script.async = true;
    script.defer = true;
    document.body.appendChild(script);

    window.handleRecaptchaCallback = (token) => {
      if (token) {
        setIsRecaptchaVerified(true);
      } else {
        setIsRecaptchaVerified(false);
      }
    };

    return () => {
      document.body.removeChild(script);
    };
  }, []);

  const handleSubmit = async (formData) => {
    const recaptchaResponse = grecaptcha.getResponse();

    if (!recaptchaResponse) {
      setError('Please verify you are not a robot.');
      return;
    };

    const recaptchaValidRes = await recaptchaVerifyAction(recaptchaResponse);

    if (recaptchaValidRes.error) {
      setError(recaptchaValidRes.error);
      return;
    };

    const result = await loginAction(formData);
    if (result.error) {
      setError(result.error);
      setSuccess('');
    } else if (result.success && result.otp) {
      setOtp(true);
      try {
        const userId = await encrypt(result.user_id);
        sessionStorage.setItem('user_id', userId);
      } catch (error) {
        console.error('Error encrypting user_id:', error);
        setError('Something went wrong. Try again');
        return;
      }
      setSuccess(result.success);
      setError('');
      sessionStorage.setItem('otpRequired', 'true');
      sessionStorage.setItem('otpExpiry', Date.now() + 600000); // 10 minutes
      router.push(`${BASE_ROUTE}/otp`);
    } else {
      setError('Something went wrong, could not send OTP. Try again');
    }
  };

  return (
    <form className={styles.form} action={handleSubmit}>
      {error && <p className={styles.error}>{error}</p>}
      {success && <p className={styles.success}>{success}</p>}
      <div className={styles.inputGroup}>
        <label htmlFor="email">Email:</label>
        <input type="email" id="email" name="email" />
      </div>
      <div className={styles.inputGroup}>
        <label htmlFor="password">Password:</label>
        <input type="password" id="password" name="password" />
      </div>
      <div
        className="g-recaptcha"
        data-sitekey={process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY}
        data-callback="handleRecaptchaCallback"
      ></div>
      <LoginButton disabled={!isRecaptchaVerified} />
      <div className={styles.actionLinks}>
        <Link href={`${BASE_ROUTE}/forgot-password`} className={styles.forgotPassword}>
          Forgot Password?
        </Link>
        {otp && (
          <Link href={`${BASE_ROUTE}/otp`} className={styles.verifyOtp}>
            Verify OTP
          </Link>
        )}
      </div>
      <div className={styles.socialLogin}>
        <GoogleLoginButton isDisabled={!isRecaptchaVerified} setError={setError} />
        <FacebookLoginButton isDisabled={!isRecaptchaVerified} setError={setError} />
        <GitHubLoginButton isDisabled={!isRecaptchaVerified} setError={setError} />
        {/* <InstagramLoginButton /> */}
        {/* <TwitterLoginButton /> */}
        {/* <LinkedInLoginButton /> */}
      </div>
    </form>
  );
};