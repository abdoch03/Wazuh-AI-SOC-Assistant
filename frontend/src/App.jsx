import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { 
  Send, 
  User, 
  Bot, 
  AlertTriangle, 
  LogOut, 
  BarChart3,
  History,
  Download,
  Shield
} from 'lucide-react'
import LoginForm from './components/LoginForm'
import ChatInterface from './components/ChatInterface'
import Dashboard from './components/Dashboard'
import HistoryPanel from './components/HistoryPanel'

// Configuration API - utilise la variable d'environnement ou fallback pour dev local
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000'
const API_URL = `${API_BASE}/api`

function App() {
  const [user, setUser] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('chat')
  const [conversations, setConversations] = useState([])
  const [dashboardData, setDashboardData] = useState(null)

  // Vérifier si l'utilisateur est déjà connecté
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await axios.get(`${API_URL}/user`, {
          withCredentials: true
        })
        setUser(response.data)
        loadDashboardData()
      } catch (error) {
        console.log('Utilisateur non connecté', error)
      }
    }
    checkAuth()
  }, [])

  const handleLogin = async (credentials) => {
    try {
      const response = await axios.post(`${API_URL}/login`, credentials, {
        withCredentials: true
      })
      setUser(response.data.user)
      loadDashboardData()
      return { success: true }
    } catch (error) {
      console.error('Erreur login:', error)
      return { 
        success: false, 
        error: error.response?.data?.error || 'Erreur de connexion' 
      }
    }
  }

  const handleLogout = async () => {
    try {
      await axios.post(`${API_URL}/logout`, {}, { withCredentials: true })
      setUser(null)
      setConversations([])
      setDashboardData(null)
    } catch (error) {
      console.error('Erreur déconnexion:', error)
    }
  }

  const loadDashboardData = async () => {
    try {
      const response = await axios.get(`${API_URL}/dashboard`, {
        withCredentials: true
      })
      setDashboardData(response.data)
    } catch (error) {
      console.error('Erreur chargement dashboard:', error)
    }
  }

  const addMessage = (message) => {
    setConversations(prev => [...prev, message])
  }

  // Debug: afficher l'URL API utilisée (à supprimer en prod)
  useEffect(() => {
    console.log('API URL utilisée:', API_URL)
  }, [])

  if (!user) {
    return <LoginForm onLogin={handleLogin} />
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <Shield className="h-8 w-8 text-blue-400" />
              <h1 className="text-xl font-bold">SOC ChatBot Assistant</h1>
            </div>
            
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-300">
                Connecté en tant que <strong>{user.full_name}</strong>
              </span>
              <button
                onClick={handleLogout}
                className="flex items-center space-x-2 px-3 py-2 bg-red-600 hover:bg-red-700 rounded-md transition-colors"
              >
                <LogOut className="h-4 w-4" />
                <span>Déconnexion</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {[
              { id: 'chat', label: 'Chat', icon: Bot },
              { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
              { id: 'history', label: 'Historique', icon: History }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-4 py-3 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-blue-400 text-blue-400'
                    : 'border-transparent text-gray-300 hover:text-white'
                }`}
              >
                <tab.icon className="h-5 w-5" />
                <span>{tab.label}</span>
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'chat' && (
          <ChatInterface
            conversations={conversations}
            onNewMessage={addMessage}
            isLoading={isLoading}
            setIsLoading={setIsLoading}
          />
        )}
        
        {activeTab === 'dashboard' && (
          <Dashboard data={dashboardData} />
        )}
        
        {activeTab === 'history' && (
          <HistoryPanel />
        )}
      </main>
    </div>
  )
}

export default App