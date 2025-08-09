import React from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'

const Landing = () => {
  const { isAuthenticated, user } = useAuth()

  const features = [
    {
      icon: '🔒',
      title: 'Bank-Grade Security',
      description: 'Your health data is protected with AES-256 encryption and blockchain-based access logging for complete transparency.'
    },
    {
      icon: '🌍',
      title: 'Global Access',
      description: 'Access your complete medical history from anywhere in the world. Emergency access available to authorized providers.'
    },
    {
      icon: '🤝',
      title: 'Consent Control',
      description: 'You decide who can access your data and for how long. Granular permissions with automatic expiry dates.'
    },
    {
      icon: '🩺',
      title: 'FHIR Compliant',
      description: 'Built on international health data standards (HL7 FHIR, DICOM) for seamless integration with any healthcare system.'
    },
    {
      icon: '🧠',
      title: 'AI-Powered Insights',
      description: 'Get personalized health insights and risk assessments powered by advanced machine learning algorithms.'
    },
    {
      icon: '📱',
      title: 'Mobile Ready',
      description: 'Access your health vault on any device with our responsive web application and upcoming mobile apps.'
    }
  ]

  const testimonials = [
    {
      name: 'Dr. Sarah Chen',
      role: 'Emergency Medicine Physician',
      content: 'Having instant access to patient history in emergencies has been life-saving. The consent system is intuitive and secure.',
      avatar: '👩‍⚕️'
    },
    {
      name: 'Michael Rodriguez',
      role: 'Chronic Disease Patient',
      content: 'Finally, I own my health data! Switching doctors is seamless when they can instantly access my complete medical history.',
      avatar: '👨'
    },
    {
      name: 'Dr. James Wilson',
      role: 'Cardiologist',
      content: 'The FHIR compliance and real-time data access have transformed how I provide care. Better data leads to better outcomes.',
      avatar: '👨‍⚕️'
    }
  ]

  const stats = [
    { value: '40B+', label: 'Global EHR Market by 2030' },
    { value: '8B', label: 'Potential Users Worldwide' },
    { value: '100%', label: 'Data Ownership for Patients' },
    { value: '24/7', label: 'Global Emergency Access' }
  ]

  return (
    <div className="min-h-screen bg-white">
      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <h1 className="text-2xl font-bold text-gradient">HealthVault</h1>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              {isAuthenticated() ? (
                <div className="flex items-center space-x-4">
                  <span className="text-gray-700">Welcome, {user?.firstName}</span>
                  <Link
                    to={user?.role === 'provider' ? '/provider/dashboard' : '/app/dashboard'}
                    className="btn btn-primary"
                  >
                    Dashboard
                  </Link>
                </div>
              ) : (
                <>
                  <Link to="/login" className="btn btn-secondary">
                    Sign In
                  </Link>
                  <Link to="/register" className="btn btn-primary">
                    Get Started
                  </Link>
                </>
              )}
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative bg-gradient-to-br from-primary-50 to-blue-50 overflow-hidden">
        <div className="absolute inset-0 bg-pattern opacity-20"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24">
          <div className="text-center">
            <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
              Your Health Data,
              <span className="text-gradient block">Everywhere You Need It</span>
            </h1>
            <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
              The world's first truly global digital health vault. Secure, encrypted, and owned by you. 
              Access your complete medical history from any doctor, any hospital, anywhere in the world.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link to="/register" className="btn btn-primary btn-lg">
                Start Your Health Vault
              </Link>
              <Link to="#features" className="btn btn-secondary btn-lg">
                Learn More
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <div key={index} className="text-center">
                <div className="text-3xl md:text-4xl font-bold text-primary-600 mb-2">
                  {stat.value}
                </div>
                <div className="text-gray-600">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Why Choose HealthVault?
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Built with cutting-edge technology and healthcare expertise to give you complete control over your health data.
            </p>
          </div>
          
          <div className="medical-grid">
            {features.map((feature, index) => (
              <div key={index} className="card hover:shadow-lg transition-shadow duration-300">
                <div className="text-4xl mb-4">{feature.icon}</div>
                <h3 className="text-xl font-semibold text-gray-900 mb-3">
                  {feature.title}
                </h3>
                <p className="text-gray-600">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              How It Works
            </h2>
            <p className="text-xl text-gray-600">
              Simple, secure, and seamless health data management
            </p>
          </div>
          
          <div className="grid md:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="bg-primary-100 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">1️⃣</span>
              </div>
              <h3 className="text-xl font-semibold mb-3">Create Your Vault</h3>
              <p className="text-gray-600">
                Sign up and create your secure health vault. Upload existing medical records or start fresh.
              </p>
            </div>
            
            <div className="text-center">
              <div className="bg-primary-100 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">2️⃣</span>
              </div>
              <h3 className="text-xl font-semibold mb-3">Connect Providers</h3>
              <p className="text-gray-600">
                Grant access to your healthcare providers with granular consent controls and automatic expiry.
              </p>
            </div>
            
            <div className="text-center">
              <div className="bg-primary-100 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">3️⃣</span>
              </div>
              <h3 className="text-xl font-semibold mb-3">Access Anywhere</h3>
              <p className="text-gray-600">
                Your complete medical history is available instantly to any authorized provider, anywhere in the world.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Testimonials */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Trusted by Healthcare Professionals
            </h2>
            <p className="text-xl text-gray-600">
              See what doctors and patients are saying about HealthVault
            </p>
          </div>
          
          <div className="grid md:grid-cols-3 gap-8">
            {testimonials.map((testimonial, index) => (
              <div key={index} className="card">
                <div className="flex items-center mb-4">
                  <div className="text-3xl mr-3">{testimonial.avatar}</div>
                  <div>
                    <h4 className="font-semibold text-gray-900">{testimonial.name}</h4>
                    <p className="text-sm text-gray-600">{testimonial.role}</p>
                  </div>
                </div>
                <p className="text-gray-700 italic">"{testimonial.content}"</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Security Section */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-6">
                Security You Can Trust
              </h2>
              <div className="space-y-4">
                <div className="flex items-start">
                  <div className="text-green-500 mr-3 mt-1">🔐</div>
                  <div>
                    <h3 className="font-semibold text-gray-900">End-to-End Encryption</h3>
                    <p className="text-gray-600">All data encrypted with AES-256 before storage</p>
                  </div>
                </div>
                <div className="flex items-start">
                  <div className="text-green-500 mr-3 mt-1">⛓️</div>
                  <div>
                    <h3 className="font-semibold text-gray-900">Blockchain Audit Trail</h3>
                    <p className="text-gray-600">Immutable logging of all data access attempts</p>
                  </div>
                </div>
                <div className="flex items-start">
                  <div className="text-green-500 mr-3 mt-1">🏥</div>
                  <div>
                    <h3 className="font-semibold text-gray-900">HIPAA Compliant</h3>
                    <p className="text-gray-600">Full compliance with healthcare privacy regulations</p>
                  </div>
                </div>
                <div className="flex items-start">
                  <div className="text-green-500 mr-3 mt-1">🚨</div>
                  <div>
                    <h3 className="font-semibold text-gray-900">Emergency Override</h3>
                    <p className="text-gray-600">Life-saving emergency access with full audit trail</p>
                  </div>
                </div>
              </div>
            </div>
            <div className="bg-gradient-to-br from-primary-50 to-blue-50 rounded-2xl p-8">
              <div className="text-center">
                <div className="text-6xl mb-4">🛡️</div>
                <h3 className="text-2xl font-bold text-gray-900 mb-4">Your Data, Your Control</h3>
                <p className="text-gray-600 mb-6">
                  Military-grade security meets user-friendly design. We never see your unencrypted data.
                </p>
                <div className="encryption-badge">
                  <span className="mr-2">🔒</span>
                  256-bit Encrypted
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-gradient-to-r from-primary-600 to-blue-600">
        <div className="max-w-4xl mx-auto text-center px-4 sm:px-6 lg:px-8">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
            Ready to Take Control of Your Health Data?
          </h2>
          <p className="text-xl text-primary-100 mb-8">
            Join thousands of patients and healthcare providers who trust HealthVault with their most important data.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link to="/register" className="btn btn-lg bg-white text-primary-600 hover:bg-gray-100">
              Create Your Vault
            </Link>
            <Link to="/login" className="btn btn-lg border-2 border-white text-white hover:bg-white hover:text-primary-600">
              Sign In
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-4 gap-8">
            <div>
              <h3 className="text-xl font-bold mb-4">HealthVault</h3>
              <p className="text-gray-400">
                The future of health data ownership and sharing.
              </p>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-gray-400">
                <li><a href="#" className="hover:text-white">Features</a></li>
                <li><a href="#" className="hover:text-white">Security</a></li>
                <li><a href="#" className="hover:text-white">API</a></li>
                <li><a href="#" className="hover:text-white">Pricing</a></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Support</h4>
              <ul className="space-y-2 text-gray-400">
                <li><a href="#" className="hover:text-white">Help Center</a></li>
                <li><a href="#" className="hover:text-white">Contact</a></li>
                <li><a href="#" className="hover:text-white">Status</a></li>
                <li><a href="#" className="hover:text-white">Community</a></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Legal</h4>
              <ul className="space-y-2 text-gray-400">
                <li><a href="#" className="hover:text-white">Privacy</a></li>
                <li><a href="#" className="hover:text-white">Terms</a></li>
                <li><a href="#" className="hover:text-white">HIPAA</a></li>
                <li><a href="#" className="hover:text-white">Compliance</a></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-gray-800 mt-8 pt-8 text-center text-gray-400">
            <p>&copy; 2024 HealthVault. All rights reserved. Built with security and privacy by design.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default Landing