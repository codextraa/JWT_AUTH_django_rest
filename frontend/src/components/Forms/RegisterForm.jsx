"use client";
import { useState, useEffect } from "react";
import { createUserAction} from "@/actions/userActions";
import { recaptchaVerifyAction } from "@/actions/authActions";
import { RegisterButton } from "../Buttons/Button";
import Link from "next/link";
import { BASE_ROUTE } from "@/route";
import { useRouter } from "next/navigation";
import styles from "./RegisterForm.module.css";

export default function RegisterForm() {
  const router = useRouter();
  const [errors, setErrors] = useState(null);
  const [isRecaptchaVerified, setIsRecaptchaVerified] = useState(false);

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
      setErrors({ error: 'Please verify you are not a robot.' });
      return;
    };

    const recaptchaValidRes = await recaptchaVerifyAction(recaptchaResponse);

    if (recaptchaValidRes.error) {
      setErrors({ error: recaptchaValidRes.error });
      return;
    };
    
    const result = await createUserAction(formData);

    if (typeof grecaptcha !== 'undefined') {
      grecaptcha.reset();
    }
    setIsRecaptchaVerified(false);
    
    if (result.error) {
      setErrors(result.error);
    } else if (result.success) {
      router.push(`${BASE_ROUTE}/auth/register/success`);
    };
  };

  return (
    <form action={handleSubmit} className={styles.form}>
      {errors && errors.error && <p className={styles.error}>{errors.error}</p>}
      <div className={styles.formGroup}>
        <label htmlFor="email" className={styles.label}>
          Email*
        </label>
        <input type="email" id="email" name="email" className={styles.input} />
      </div>
      {errors && errors.email && <p className={styles.error}>{errors.email}</p>}
      <div className={styles.formGroup}>
        <label htmlFor="username" className={styles.label}>
          Username
        </label>
        <input type="text" id="username" name="username" className={styles.input} />
      </div>
      {errors && errors.username && <p className={styles.error}>{errors.username}</p>}
      <div className={styles.formGroup}>
        <label htmlFor="first_name" className={styles.label}>
          First Name
        </label>
        <input type="text" id="first_name" name="first_name" className={styles.input} />
      </div>
      {errors && errors.first_name && <p className={styles.error}>{errors.first_name}</p>}
      <div className={styles.formGroup}>
        <label htmlFor="last_name" className={styles.label}>
          Last Name
        </label>
        <input type="text" id="last_name" name="last_name" className={styles.input} />
      </div>
      {errors && errors.last_name && <p className={styles.error}>{errors.last_name}</p>}
      <div className={styles.formGroup}>
        <label htmlFor="phone_number" className={styles.label}>
          Phone Number
        </label>
        <input type="tel" id="phone_number" name="phone_number" pattern="[+0-9\s()-]*" className={styles.input} />
        <small className={styles.small}>Phone number must contain country code.</small>
      </div>
      {errors && errors.phone_number && <p className={styles.error}>{errors.phone_number}</p>}
      <div className={styles.formGroup}>
        <label htmlFor="password" className={styles.label}>
          Password*
        </label>
        <input type="password" id="password" name="password" className={styles.input} />
        <small className={styles.small}>
          Password must be at least 8 characters.
          <span className={styles.line}>Must include at least
            one uppercase letter, 
            one lowercase letter, 
            one number, 
            one special character. 
          </span>
        </small>
      </div>
      {errors && errors.password && <p className={styles.error}>{errors.password}</p>}
      <div className={styles.formGroup}>
        <label htmlFor="c_password" className={styles.label}>
          Confirm Password*
        </label>
        <input type="password" id="c_password" name="c_password" className={styles.input} />
      </div>
      {errors && errors.c_password && <p className={styles.error}>{errors.c_password}</p>}
      <div
        className="g-recaptcha"
        data-sitekey={process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY}
        data-callback="handleRecaptchaCallback"
      ></div>
      <RegisterButton disabled={!isRecaptchaVerified}/>
      <Link href="/login" className={styles.link}>
        Back to Login
      </Link>
    </form>
  );
};

