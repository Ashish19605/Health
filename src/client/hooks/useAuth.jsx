import React, { createContext, useContext, useState, useEffect } from 'react'

const AuthContext = createContext({})

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(localStorage.getItem('token'))
  const [loading, setLoading] = useState(true)

  // API Base URL
  const API_BASE = import.meta.env.VITE_API_URL || '/api'

  // Initialize auth state
  useEffect(() => {
    const initAuth = async () => {
      const storedToken = localStorage.getItem('token')
      if (storedToken) {
        try {
          const user = await getCurrentUser(storedToken)
          setUser(user)
          setToken(storedToken)
        } catch (error) {
          console.error('Auth initialization failed:', error)
          localStorage.removeItem('token')
          setToken(null)
        }
      }
      setLoading(false)
    }

    initAuth()
  }, [])

  // Get current user from token
  const getCurrentUser = async (authToken) => {
    const response = await fetch(`${API_BASE}/auth/me`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    })

    if (!response.ok) {
      throw new Error('Failed to get user')
    }

    const data = await response.json()
    return data.data.user
  }

  // Login function
  const login = async (email, password) => {
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.message || 'Login failed')
      }

      const { user, token } = data.data
      
      localStorage.setItem('token', token)
      setToken(token)
      setUser(user)

      return { success: true, user }
    } catch (error) {
      console.error('Login error:', error)
      throw error
    }
  }

  // Register function
  const register = async (userData) => {
    try {
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.message || 'Registration failed')
      }

      const { user, token } = data.data
      
      localStorage.setItem('token', token)
      setToken(token)
      setUser(user)

      return { success: true, user }
    } catch (error) {
      console.error('Registration error:', error)
      throw error
    }
  }

  // Logout function
  const logout = async () => {
    try {
      if (token) {
        await fetch(`${API_BASE}/auth/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        })
      }
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      localStorage.removeItem('token')
      setToken(null)
      setUser(null)
    }
  }

  // Change password function
  const changePassword = async (currentPassword, newPassword) => {
    try {
      const response = await fetch(`${API_BASE}/auth/change-password`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ currentPassword, newPassword })
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.message || 'Password change failed')
      }

      return { success: true }
    } catch (error) {
      console.error('Change password error:', error)
      throw error
    }
  }

  // Update user profile
  const updateProfile = async (profileData) => {
    try {
      const response = await fetch(`${API_BASE}/users/profile`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(profileData)
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.message || 'Profile update failed')
      }

      setUser(data.data.user)
      return { success: true, user: data.data.user }
    } catch (error) {
      console.error('Profile update error:', error)
      throw error
    }
  }

  // Refresh token function
  const refreshToken = async () => {
    try {
      const response = await fetch(`${API_BASE}/auth/refresh-token`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error('Token refresh failed')
      }

      const newToken = data.data.token
      localStorage.setItem('token', newToken)
      setToken(newToken)

      return newToken
    } catch (error) {
      console.error('Token refresh error:', error)
      logout() // Force logout if refresh fails
      throw error
    }
  }

  // API request helper with automatic token refresh
  const apiRequest = async (url, options = {}) => {
    try {
      const response = await fetch(`${API_BASE}${url}`, {
        ...options,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          ...options.headers
        }
      })

      // Handle token expiration
      if (response.status === 401 && token) {
        try {
          const newToken = await refreshToken()
          // Retry with new token
          return fetch(`${API_BASE}${url}`, {
            ...options,
            headers: {
              'Authorization': `Bearer ${newToken}`,
              'Content-Type': 'application/json',
              ...options.headers
            }
          })
        } catch (refreshError) {
          logout()
          throw new Error('Session expired')
        }
      }

      return response
    } catch (error) {
      console.error('API request error:', error)
      throw error
    }
  }

  // Check if user has specific role
  const hasRole = (role) => {
    return user?.role === role
  }

  // Check if user has any of the specified roles
  const hasAnyRole = (roles) => {
    return roles.includes(user?.role)
  }

  // Check if user is authenticated
  const isAuthenticated = () => {
    return !!user && !!token
  }

  // Check if user's email is verified
  const isEmailVerified = () => {
    return user?.emailVerified === true
  }

  // Check if user is a verified provider
  const isVerifiedProvider = () => {
    return user?.role === 'provider' && 
           user?.providerInfo?.verificationStatus === 'verified'
  }

  const value = {
    user,
    token,
    loading,
    login,
    register,
    logout,
    changePassword,
    updateProfile,
    refreshToken,
    apiRequest,
    hasRole,
    hasAnyRole,
    isAuthenticated,
    isEmailVerified,
    isVerifiedProvider
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}