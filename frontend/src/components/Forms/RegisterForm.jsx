"use client";
import { useState } from "react";
import { createUserAction } from "../actions/userActions";
import { RegisterButton } from "../Buttons/Button";
import Link from "next/link";
import { BASE_ROUTE } from "@/route";
import { useRouter } from "next/navigation";
import styles from "./RegisterForm.module.css";

export default function RegisterForm() {
  const [errors, setErrors] = useState({});
  const router = useRouter();

  const handleSubmit = async (formData) => {
    const result = await createUserAction(formData);
    if (result.error) {
      setErrors(result.error);
    } else if (result.success) {
      router.push(`${BASE_ROUTE}/auth/register/success`);
    };
  };

  return (
    <form action={handleSubmit} className={styles.form}>
      {error && <p className={styles.error}>{error}</p>}
      <div className={styles.formGroup}>
        <label htmlFor="email" className={styles.label}>
          Email
        </label>
        <input type="email" id="email" name="email" required className={styles.input} />
      </div>
      <div className={styles.formGroup}>
        <label htmlFor="first_name" className={styles.label}>
          First Name
        </label>
        <input type="text" id="first_name" name="first_name" required className={styles.input} />
      </div>
      <div className={styles.formGroup}>
        <label htmlFor="last_name" className={styles.label}>
          Last Name
        </label>
        <input type="text" id="last_name" name="last_name" required className={styles.input} />
      </div>
      <div className={styles.formGroup}>
        <label htmlFor="phone_number" className={styles.label}>
          Last Name
        </label>
        <input type="text" id="phone_number" name="phone_number" required className={styles.input} />
        <small className={styles.small}>Phone number must contain country code.</small>
      </div>
      <div className={styles.formGroup}>
        <label htmlFor="password" className={styles.label}>
          Password
        </label>
        <input type="password" id="password" name="password" required className={styles.input} />
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
      <div className={styles.formGroup}>
        <label htmlFor="c_password" className={styles.label}>
          Confirm Password
        </label>
        <input type="password" id="c_password" name="c_password" required className={styles.input} />
      </div>
      <RegisterButton />
      <Link href="/login" className={styles.link}>
        Back to Login
      </Link>
    </form>
  );
};

