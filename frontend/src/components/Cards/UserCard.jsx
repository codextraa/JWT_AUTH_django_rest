"use client";
import Link from "next/link";
import { BASE_ROUTE } from "@/route";
import styles from "./UserCard.module.css";

export default function UserCard({ user, userRole, onActivate, onDeactivate, onDelete }) {
  return (
    <div className={styles.card}>
      <h3>{user.email}</h3>
      <p>Username: {user.username}</p>
      <p>Status: {user.is_active ? "Active" : "Inactive"}</p>
      <p>Admin: {user.is_staff ? "Yes" : "No"}</p>
      <div className={styles.actions}>
        {user.is_active ? (
          <button onClick={() => onDeactivate(user.id)} className={styles.deactivateButton}>
            Deactivate
          </button>
        ) : (
          <button onClick={() => onActivate(user.id)} className={styles.activateButton}>
            Activate
          </button>
        )}
        {userRole === "Superuser" && (
          <>
            <Link href={`${BASE_ROUTE}/profile/${user.id}`} className={styles.editButton}>
              Edit
            </Link>
            <button onClick={() => onDelete(user.id)} className={styles.deleteButton}>
              Delete
            </button>
          </>
        )}
      </div>
    </div>
  );
};