'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { loginAction } from '@/actions/authActions';
import { BASE_ROUTE } from '@/route';
import { encrypt } from '@/libs/session';
import styles from './LoginForm.module.css';
import { 
  LoginButton,
  GoogleLoginButton,
  FacebookLoginButton,
  InstagramLoginButton,
  TwitterLoginButton,
  LinkedInLoginButton,
  GitHubLoginButton,
} from '../Buttons/Button';

export default function LoginForm() {
  const router = useRouter();
  const [otp, setOtp] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

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

  const handleSubmit = async (formData) => {
    const action = formData.get('action');
    console.log(action);
    // const result = await loginAction(formData);
    // if (result.error) {
    //   setError(result.error);
    //   setSuccessMessage('');
    // } else if (result.success && result.otp) {
    //   // Store OTP status in sessionStorage
    //   setOtp(true);
    //   try {
    //     const userId = await encrypt(result.user_id);
    //     sessionStorage.setItem('user_id', userId);
    //   } catch (error) {
    //     console.log('Error encrypting user_id:', error);
    //     setError('Something went wrong. Try again');
    //     return
    //   };
    //   setSuccessMessage(result.success);
    //   setError('');
    //   sessionStorage.setItem('otpRequired', 'true');
    //   sessionStorage.setItem('otpExpiry', Date.now() + 600000); // 10 minutes
    //   router.push(`${BASE_ROUTE}/otp`);
    // } else {
    //   setError('Something went wrong, could not send OTP. Try again');
    // };
  };

  return (
    <form className={styles.form} action={handleSubmit}>
      {error && <p className={styles.error}>{error}</p>}
      {successMessage && <p className={styles.success}>{successMessage}</p>}
      <div className={styles.inputGroup}>
        <label htmlFor="email">Email:</label>
        <input type="email" id="email" name="email"/>
      </div>
      <div className={styles.inputGroup}>
        <label htmlFor="password">Password:</label>
        <input type="password" id="password" name="password"/>
      </div>
      <LoginButton />
      <div className={styles.actionLinks}>
        <Link href={`${BASE_ROUTE}/forgot-password`} className={styles.forgotPassword}>
          Forgot Password?
        </Link>
        {otp && 
        <Link href={`${BASE_ROUTE}/otp`} className={styles.verifyOtp}>
          Verify OTP
        </Link>}
      </div>
      <div className={styles.socialLogin}>
        <GoogleLoginButton />
        <FacebookLoginButton />
        <InstagramLoginButton />
        <LinkedInLoginButton />
        <GitHubLoginButton />
        <TwitterLoginButton />
      </div>
    </form>
  );
};