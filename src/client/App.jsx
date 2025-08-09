import React from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './hooks/useAuth'
import { ProtectedRoute } from './components/ProtectedRoute'

// Pages
import Landing from './pages/Landing'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import HealthRecords from './pages/HealthRecords'
import ConsentManagement from './pages/ConsentManagement'
import Profile from './pages/Profile'
import ProviderDashboard from './pages/ProviderDashboard'
import NotFound from './pages/NotFound'

// Layout
import Layout from './components/Layout'

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="min-h-screen bg-gray-50">
          <Routes>
            {/* Public Routes */}
            <Route path="/" element={<Landing />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            
            {/* Protected Routes */}
            <Route path="/app" element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }>
              <Route index element={<Navigate to="/app/dashboard" replace />} />
              <Route path="dashboard" element={<Dashboard />} />
              <Route path="health-records" element={<HealthRecords />} />
              <Route path="consent" element={<ConsentManagement />} />
              <Route path="profile" element={<Profile />} />
            </Route>
            
            {/* Provider Routes */}
            <Route path="/provider" element={
              <ProtectedRoute requiredRole="provider">
                <Layout />
              </ProtectedRoute>
            }>
              <Route index element={<Navigate to="/provider/dashboard" replace />} />
              <Route path="dashboard" element={<ProviderDashboard />} />
              <Route path="patients" element={<div>Patient Management</div>} />
              <Route path="records" element={<div>Patient Records</div>} />
            </Route>
            
            {/* Admin Routes */}
            <Route path="/admin" element={
              <ProtectedRoute requiredRole="admin">
                <Layout />
              </ProtectedRoute>
            }>
              <Route index element={<Navigate to="/admin/dashboard" replace />} />
              <Route path="dashboard" element={<div>Admin Dashboard</div>} />
              <Route path="users" element={<div>User Management</div>} />
              <Route path="audit" element={<div>Audit Logs</div>} />
            </Route>
            
            {/* 404 Route */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  )
}

export default App