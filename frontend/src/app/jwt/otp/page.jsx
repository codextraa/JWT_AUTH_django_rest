'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { verifyOtpAction } from '@/actions/authActions';
import { OtpVerifyButton, ResendOtpButton } from '@/components/Button';
import { BASE_ROUTE, DEFAULT_LOGIN_REDIRECT } from '@/route';
import styles from './page.module.css';

export default function OtpPage() {
  const router = useRouter();
  const [timer, setTimer] = useState(60);
  const [canResend, setCanResend] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  useEffect(() => {
    const otpRequired = sessionStorage.getItem('otpRequired');
    const otpExpiry = sessionStorage.getItem('otpExpiry');

    if (!otpRequired || Date.now() > parseInt(otpExpiry, 10)) {
      router.push(`${BASE_ROUTE}/login`);
    }

    const interval = setInterval(() => {
      setTimer((prevTimer) => {
        if (prevTimer === 0) {
          setCanResend(true);
          clearInterval(interval);
          return 0;
        }
        return prevTimer - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [router]);

  const handleSubmit = async (formData) => {
    const result = await verifyOtpAction(formData);
    if (result.error) {
      setError(result.error);
      setSuccessMessage('');
    } else if (result.success) {
      setSuccessMessage(result.success);
      setError('');
      sessionStorage.removeItem('otpRequired');
      sessionStorage.removeItem('otpExpiry');
      router.push(`${DEFAULT_LOGIN_REDIRECT}`);
    }
  };

  const handleResendOtp = async () => {
    // Implement OTP resend logic here
    // For now, we'll just reset the timer and disable the resend button
    setTimer(60);
    setCanResend(false);
    // You would typically call an API endpoint to resend the OTP here
  };

  return (
    <div className={styles.container}>
      <h1 className={styles.title}>OTP Verification</h1>
      <form className={styles.form} action={handleSubmit}>
        <div className={styles.inputGroup}>
          <label htmlFor="otp">Enter OTP:</label>
          <input type="text" id="otp" name="otp" required />
        </div>
        <OtpVerifyButton />
        <ResendOtpButton
        onClick={handleResendOtp}
        disabled={!canResend}
        timer={timer}
        />
      </form>
      {error && <p className={styles.error}>{error}</p>}
      {successMessage && <p className={styles.success}>{successMessage}</p>}
    </div>
  );
}