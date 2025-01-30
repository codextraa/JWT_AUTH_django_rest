"use client"

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  getUserAction,
  updateUserAction,
  uploadProfileImageAction,
  deactivateUserAction,
} from "@/actions/userActions";
import { BASE_ROUTE } from "@/route";
import { getUserIdFromSession } from "@/libs/cookie";
import ProfileImage from "@/components/Modals/ProfileImageModal"
import DeactivateModal from "@/components/Modals/DeactivateModal";
import { UpdateButton, UploadImageButton } from "@/components/Buttons/Button";
import styles from "./page.module.css"

export default function ProfilePage({ params }) {
  const [user, setUser] = useState(null)
  const [error, setError] = useState("")
  const router = useRouter()

  useEffect(() => {
    fetchUser()
  }, [])

  const fetchUser = async () => {
    const result = await getUserAction(params.id)
    if (result.user) {
      setUser(result.user)
    } else {
      setError(result.error)
    }
  }

  const handleUpdate = async (formData) => {
    const result = await updateUserAction(params.id, formData)
    if (result.success) {
      fetchUser()
    } else {
      setError(result.error)
    }
  }

  const handleUpload = async (file) => {
    const formData = new FormData()
    formData.append("profile_img", file)
    const result = await uploadProfileImageAction(params.id, formData)
    if (result.success) {
      fetchUser()
    } else {
      setError(result.error)
    }
  }

  const handleDeactivate = async () => {
    const result = await deactivateUserAction(params.id)
    if (result.success) {
      router.push(`${BASE_ROUTE}/auth/login`)
    } else {
      setError(result.error)
    }
  }

  if (!user) {
    return <div>Loading...</div>
  }

  return (
    <div className={styles.container}>
      <h1 className={styles.title}>User Profile</h1>
      <ProfileImage src={user.profile_img} alt={user.username} />
      <UploadImageButton onUpload={handleUpload} />
      <form action={handleUpdate} className={styles.form}>
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
        <UpdateButton />
      </form>
      {getUserIdFromSession() === params.id && <DeactivateModal onDeactivate={handleDeactivate} />}
      {error && <p className={styles.error}>{error}</p>}
    </div>
  )
}