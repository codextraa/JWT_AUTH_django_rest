'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { loginAction } from '@/actions/authActions';
import { LoginButton } from './Button';
import { BASE_ROUTE } from '@/route';
import styles from './LoginForm.module.css';

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
    const result = await loginAction(formData);
    console.log('result', result);
    if (result.error) {
      setError(result.error);
      setSuccessMessage('');
    } else if (result.success) {
      setSuccessMessage(result.success);
      setError('');
      if (result.otp) {
        // Store OTP status in sessionStorage
        setOtp(true);
        sessionStorage.setItem('otpRequired', 'true');
        sessionStorage.setItem('otpExpiry', Date.now() + 600000); // 10 minutes
        router.push(`${BASE_ROUTE}/otp`);
      } else {
        setError('Something went wrong, could not send OTP. Try again');
      };
    };
  };

  return (
    <form className={styles.form} action={handleSubmit}>
      {error && <p className={styles.error}>{error}</p>}
      {successMessage && <p className={styles.success}>{successMessage}</p>}
      <div className={styles.inputGroup}>
        <label htmlFor="email">Email:</label>
        <input type="email" id="email" name="email" required />
      </div>
      <div className={styles.inputGroup}>
        <label htmlFor="password">Password:</label>
        <input type="password" id="password" name="password" required />
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
    </form>
  );
};