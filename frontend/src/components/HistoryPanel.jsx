import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { History, Search, Download, Calendar, User, AlertTriangle, Clock } from 'lucide-react'

const API_BASE = 'http://localhost:5000/api'

const HistoryPanel = () => {
  const [conversations, setConversations] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [selectedConversation, setSelectedConversation] = useState(null)
  const [exporting, setExporting] = useState(false)

  const perPage = 10

  useEffect(() => {
    loadHistory()
  }, [currentPage, searchTerm])

  const loadHistory = async () => {
    try {
      setLoading(true)
      const response = await axios.get(`${API_BASE}/history`, {
        params: {
          page: currentPage,
          per_page: perPage,
          search: searchTerm || undefined
        },
        withCredentials: true
      })
      
      setConversations(response.data.conversations)
      setTotalPages(response.data.pagination.pages)
      setError('')
    } catch (error) {
      setError('Erreur lors du chargement de l\'historique')
      console.error('Erreur:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleExport = async (conversationId, format = 'json') => {
    try {
      setExporting(true)
      const response = await axios.post(`${API_BASE}/export/conversation`, {
        conversation_id: conversationId,
        format: format
      }, {
        withCredentials: true
      })

      const data = response.data.data
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json'
      })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `soc-chatbot-${conversationId}-${new Date().toISOString().split('T')[0]}.json`
      link.click()
      URL.revokeObjectURL(url)

    } catch (error) {
      console.error('Erreur export:', error)
      alert('Erreur lors de l\'export')
    } finally {
      setExporting(false)
    }
  }

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('fr-FR', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const truncateText = (text, length = 80) => {
    return text.length > length ? text.substring(0, length) + '...' : text
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400"></div>
      </div>
    )
  }

  return (
    <div className="bg-gray-800 rounded-lg shadow-lg p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <History className="h-6 w-6 text-blue-400" />
          <h2 className="text-xl font-semibold text-white">Historique des Conversations</h2>
        </div>
        
        <div className="flex items-center space-x-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Rechercher..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-600/20 border border-red-600 text-red-400 px-4 py-3 rounded-md mb-6">
          {error}
        </div>
      )}

      {/* Conversations List */}
      <div className="space-y-4">
        {conversations.length === 0 ? (
          <div className="text-center py-12 text-gray-400">
            <History className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>Aucune conversation dans l'historique</p>
          </div>
        ) : (
          conversations.map((conversation) => (
            <div
              key={conversation.id}
              className={`bg-gray-700 rounded-lg p-4 border-l-4 ${
                conversation.is_critical ? 'border-red-500' : 'border-gray-600'
              } hover:bg-gray-600 transition-colors cursor-pointer`}
              onClick={() => setSelectedConversation(selectedConversation?.id === conversation.id ? null : conversation)}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <User className="h-4 w-4 text-gray-400" />
                    <span className="text-sm text-gray-300">{conversation.user_name}</span>
                    {conversation.is_critical && (
                      <AlertTriangle className="h-4 w-4 text-red-400" />
                    )}
                  </div>
                  
                  <div className="mb-2">
                    <p className="text-white font-medium mb-1">
                      {truncateText(conversation.question)}
                    </p>
                    <p className="text-gray-400 text-sm">
                      {truncateText(conversation.response.replace(/[#*`]/g, ''), 100)}
                    </p>
                  </div>

                  <div className="flex items-center space-x-4 text-xs text-gray-500">
                    <div className="flex items-center space-x-1">
                      <Calendar className="h-3 w-3" />
                      <span>{formatDate(conversation.created_at)}</span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Clock className="h-3 w-3" />
                      <span>{conversation.response_time_ms}ms</span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    handleExport(conversation.id)
                  }}
                  disabled={exporting}
                  className="ml-4 p-2 text-gray-400 hover:text-white hover:bg-gray-600 rounded-md transition-colors"
                  title="Exporter la conversation"
                >
                  <Download className="h-4 w-4" />
                </button>
              </div>

              {/* Expanded View */}
              {selectedConversation?.id === conversation.id && (
                <div className="mt-4 pt-4 border-t border-gray-600">
                  <div className="bg-gray-800 rounded-md p-4 mb-3">
                    <h4 className="text-sm font-medium text-gray-300 mb-2">Question:</h4>
                    <p className="text-white">{conversation.question}</p>
                  </div>
                  
                  <div className="bg-gray-800 rounded-md p-4">
                    <h4 className="text-sm font-medium text-gray-300 mb-2">Réponse:</h4>
                    <div className="prose prose-invert max-w-none text-sm">
                      <div dangerouslySetInnerHTML={{ 
                        __html: conversation.response.replace(/\n/g, '<br/>')
                      }} />
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center items-center space-x-2 mt-6 pt-6 border-t border-gray-700">
          <button
            onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
            disabled={currentPage === 1}
            className="px-3 py-2 bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-md text-white hover:bg-gray-600 transition-colors"
          >
            Précédent
          </button>
          
          <span className="text-sm text-gray-400">
            Page {currentPage} sur {totalPages}
          </span>
          
          <button
            onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
            disabled={currentPage === totalPages}
            className="px-3 py-2 bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-md text-white hover:bg-gray-600 transition-colors"
          >
            Suivant
          </button>
        </div>
      )}
    </div>
  )
}

export default HistoryPanel