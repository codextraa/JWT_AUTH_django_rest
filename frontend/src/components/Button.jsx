'use client';

import { useFormStatus } from 'react-dom';
import styles from './Button.module.css';

export const LoginButton = () => {
  const { pending } = useFormStatus();

  return (
    <button type="submit" disabled={pending} className={styles.loginButton}>
      {pending ? 'Logging in...' : 'Login'}
    </button>
  );
}

export const OtpVerifyButton = () => {
  const { pending } = useFormStatus();

  return (
    <button type="submit" disabled={pending} className={styles.otpVerifyButton}>
      {pending ? 'Verifying...' : 'Verify OTP'}
    </button>
  );
}

export const ResendOtpButton = ({ onClick, disabled, timer }) => {
  const { pending } = useFormStatus();

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || pending}
      className={styles.resendOtpButton}
    >
      {pending ? 'Resending...' : disabled ? `Resend OTP (${timer}s)` : 'Resend OTP'}
    </button>
  );
}