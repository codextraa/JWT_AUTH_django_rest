"use client";
import styles from "./Sidebar.module.css";


export default function Sidebar({ onFilterChange }) {
  return (
    <div className={styles.sidebar}>
      <div className={styles.filterGroup}>
        <h3>User Group</h3>
        <select onChange={(e) => onFilterChange("group", e.target.value)} className={styles.select}>
          <option value="">All</option>
          <option value="Default">Users</option>
          <option value="Admin">Admin</option>
          <option value="Superuser">Superuser</option>
        </select>
      </div>
      <div className={styles.filterGroup}>
        <h3>User Status</h3>
        <select onChange={(e) => onFilterChange("is_active", e.target.value)} className={styles.select}>
          <option value="">All</option>
          <option value="true">Active</option>
          <option value="false">Inactive</option>
        </select>
      </div>
      <div className={styles.filterGroup}>
        <h3>Page Size</h3>
        <select onChange={(e) => onFilterChange("page_size", e.target.value)} className={styles.select}>
          <option value="0">Default</option>
          <option value="10">10</option>
          <option value="20">20</option>
          <option value="50">50</option>
        </select>
      </div>
    </div>
  );
};