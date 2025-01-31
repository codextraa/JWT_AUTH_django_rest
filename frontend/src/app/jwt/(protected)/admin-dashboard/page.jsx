"use client";
import { useState, useEffect } from "react";
import { 
  getUsersAction, 
  deleteUserAction, 
  activateUserAction, 
  deactivateUserAction 
} from "@/actions/userActions";
import { getUserRoleAction } from "@/actions/authActions";
import SearchBar from "@/components/Admin-Comps/SearchBar";
import Sidebar from "@/components/Admin-Comps/Sidebar";
import UserCard from "@/components/Cards/UserCard";
import Pagination from "@/components/Admin-Comps/Pagination";
import styles from "./page.module.css";


export default function AdminDashboard() {
  const [users, setUsers] = useState([])
  const [pagination, setPagination] = useState(null)
  const [filters, setFilters] = useState({
    search: "",
    group: "",
    is_active: "",
    page: 1,
    page_size: 0,
  })
  const [userRole, setUserRole] = useState(null)
  const [isFiltered, setIsFiltered] = useState(false)
  const [successMessage, setSuccessMessage] = useState("")
  const [errorMessage, setErrorMessage] = useState("")

  useEffect(() => {
    const fetchUserRole = async () => {
      const role = await getUserRoleAction()
      setUserRole(role)
    }
    fetchUserRole()
  }, [])

  useEffect(() => {
    fetchUsers()
  }, [filters.page, filters.page_size, filters.search, filters.group, filters.is_active])

  const fetchUsers = async () => {
    try {
      const result = await getUsersAction(filters)
      if (result.data) {
        setUsers(result.data)
        setPagination(result.pagination)
      } else if (result.error) {
        setErrorMessage(result.error)
      }
    } catch (error) {
      setErrorMessage("Failed to fetch users.")
    }
  }

  const handleSearch = (searchTerm) => {
    setFilters((prev) => ({ ...prev, search: searchTerm, page: 1 }))
    setIsFiltered(true)
  }

  const handleFilterChange = (filterName, value) => {
    setFilters((prev) => ({ ...prev, [filterName]: value, page: 1 }))
    setIsFiltered(true)
  }

  const handlePageChange = (newPage) => {
    setFilters((prev) => ({ ...prev, page: newPage }))
  }

  const handleShowAll = () => {
    setFilters({
      search: "",
      group: "",
      is_active: "",
      page: 1,
      page_size: "0",
    })
    setIsFiltered(false)
  }

  const handleActivate = async (id) => {
    try {
      const result = await activateUserAction(id)
      if (result.success) {
        setSuccessMessage(result.success)
      } else if (result.error) {
        setErrorMessage(result.error)
      }
    } catch (error) {
      setErrorMessage("Failed to activate user.")
    }
    fetchUsers()
    clearMessages()
  }

  const handleDeactivate = async (id) => {
    try {
      const result = await deactivateUserAction(id)
      if (result.success) {
        setSuccessMessage(result.success)
      } else if (result.error) {
        setErrorMessage(result.error)
      }
    } catch (error) {
      setErrorMessage("Failed to deactivate user.")
    }
    fetchUsers()
    clearMessages()
  }

  const handleDelete = async (id) => {
    try {
      const result = await deleteUserAction(id)
      if (result.success) {
        setSuccessMessage(result.success)
      } else if (result.error) {
        setErrorMessage(result.error)
      }
    } catch (error) {
      setErrorMessage("Failed to delete user.")
    }
    fetchUsers()
    clearMessages()
  }

  const clearMessages = () => {
    setTimeout(() => {
      setSuccessMessage("")
      setErrorMessage("")
    }, 5000)
  }

  if (userRole !== "Admin" && userRole !== "Superuser") {
    return <div>Access Denied. You must be an Admin or Superuser to view this page.</div>
  }

  return (
    <div className={styles.dashboard}>
      <Sidebar onFilterChange={handleFilterChange} />
      <div className={styles.content}>
        <h1>Admin Dashboard</h1>
        <div className={styles.controls}>
          <SearchBar onSearch={handleSearch} />
          {isFiltered && (
            <button onClick={handleShowAll} className={styles.showAllButton}>
              Show All
            </button>
          )}
        </div>
        {successMessage && <div className={styles.successMessage}>{successMessage}</div>}
        {errorMessage && <div className={styles.errorMessage}>{errorMessage}</div>}
        <div className={styles.userGrid}>
          {users.map((user) => (
            <UserCard
              key={user.id}
              user={user}
              userRole={userRole}
              onActivate={handleActivate}
              onDeactivate={handleDeactivate}
              onDelete={handleDelete}
            />
          ))}
        </div>
        {pagination && (
          <Pagination
            currentPage={filters.page}
            totalPages={Math.ceil(pagination.count / filters.page_size)}
            onPageChange={handlePageChange}
          />
        )}
      </div>
    </div>
  )
}
