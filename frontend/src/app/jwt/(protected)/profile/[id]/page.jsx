"use client"

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  getUserAction,
  updateUserAction,
  uploadProfileImageAction,
  deactivateUserAction,
} from "@/actions/userActions";
import { getUserIdAction } from "@/actions/authActions";
import { BASE_ROUTE } from "@/route";
import ProfileImage from "@/components/Modals/ProfileImageModal"
import DeactivateModal from "@/components/Modals/DeactivateModal";
import { UpdateButton, UploadImageButton } from "@/components/Buttons/Button";
import styles from "./page.module.css";

export default function ProfilePage({ params }) {
  const [isDeactivateOpen, setIsDeactivateOpen] = useState(false);
  const [user, setUser] = useState(null);
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();

  useEffect(() => {
    fetchUser();
  }, []);

  const fetchUser = async () => {
    const params_obj = await params;
    const user_id = await getUserIdAction();
    setIsDeactivateOpen(user_id === params_obj.id);
    const result = await getUserAction(params_obj.id);
    if (result.data) {
      setUser(result.data);
      setError("");
    } else {
      setError(result.error);
    };
  };

  const handleUpdate = async (formData) => {
    const params_obj = await params;
    const result = await updateUserAction(params_obj.id, formData);
    if (result.success) {
      fetchUser();
      setSuccess(result.success);
      setError("");
    } else {
      setSuccess("");
      setError(result.error);
    };
  };

  const handleUpload = async (file) => {
    if (file.size > 2 * 1024 * 1024) { // 2 MB limit
      setSuccess("");
      setError("File size exceeds 2MB. Please upload a smaller image.");
      return;
    }

    const params_obj = await params;
    const formData = new FormData();
    formData.append("profile_img", file);
    const result = await uploadProfileImageAction(params_obj.id, formData);
    if (result.success) {
      fetchUser();
      setSuccess(result.success);
      setError("");
    } else {
      setSuccess("");
      setError(result.error);
    };
  };

  const handleDeactivate = async () => {
    const params_obj = await params;
    const result = await deactivateUserAction(params_obj.id);
    if (result.success) {
      setSuccess(result.success);
      setError("");
      router.push(`${BASE_ROUTE}/auth/login`);
    } else {
      setSuccess("");
      setError(result.error);
    };
  };

  if (!user) {
    return <div className={styles.loading}>Loading...</div>
  };

  return (
    <div className={styles.container}>
      <h1 className={styles.title}>User Profile</h1>
      {error && <p className={styles.error}>{error}</p>}
      {success && <p className={styles.success}>{success}</p>}
      <div className={styles.profile}>
        <ProfileImage src={user.profile_img} alt={user.username} />
        <UploadImageButton onUpload={handleUpload} />
      </div>
      <form action={handleUpdate} className={styles.form}>
        <h2 className={styles.title}>Update Profile</h2>
        <div className={styles.formGroup}>
          <label htmlFor="email">Email</label>
          <input type="email" id="email" name="email" value={user.email} disabled />
        </div>
        <div className={styles.formGroup}>
          <label htmlFor="username">Username</label>
          <input type="text" id="username" name="username" defaultValue={user.username} />
        </div>
        <div className={styles.formGroup}>
          <label htmlFor="first_name">First Name</label>
          <input type="text" id="first_name" name="first_name" defaultValue={user.first_name} />
        </div>
        <div className={styles.formGroup}>
          <label htmlFor="last_name">Last Name</label>
          <input type="text" id="last_name" name="last_name" defaultValue={user.last_name} />
        </div>
        <div className={styles.formGroup}>
          <label htmlFor="phone_number">Phone Number</label>
          <input type="tel" id="phone_number" name="phone_number" defaultValue={user.phone_number} />
        </div>
        <div className={styles.buttons}>
          <UpdateButton />
          {isDeactivateOpen && <DeactivateModal onDeactivate={handleDeactivate} />}
        </div>
      </form>
    </div>
  );
};