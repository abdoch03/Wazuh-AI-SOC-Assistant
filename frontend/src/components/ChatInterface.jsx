import React, { useState, useRef, useEffect } from 'react'
import axios from 'axios'
import { Send, Bot, User, AlertTriangle, Download } from 'lucide-react'
import ReactMarkdown from 'react-markdown'

const API_BASE = 'http://localhost:5000/api'

const ChatInterface = ({ conversations, onNewMessage, isLoading, setIsLoading }) => {
  const [inputMessage, setInputMessage] = useState('')
  const [sessionId] = useState(() => Date.now().toString())
  const messagesEndRef = useRef(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [conversations])

  const handleSendMessage = async (e) => {
    e.preventDefault()
    if (!inputMessage.trim() || isLoading) return

    const userMessage = {
      type: 'user',
      content: inputMessage,
      timestamp: new Date().toISOString()
    }

    onNewMessage(userMessage)
    setInputMessage('')
    setIsLoading(true)

    try {
      const response = await axios.post(`${API_BASE}/chat`, {
        question: inputMessage,
        session_id: sessionId
      }, {
        withCredentials: true
      })

      const botMessage = {
        type: 'bot',
        content: response.data.response,
        isCritical: response.data.is_critical,
        timestamp: response.data.timestamp,
        responseTime: response.data.response_time_ms
      }

      onNewMessage(botMessage)
    } catch (error) {
      const errorMessage = {
        type: 'bot',
        content: '❌ Erreur de connexion avec le serveur',
        isError: true,
        timestamp: new Date().toISOString()
      }
      onNewMessage(errorMessage)
    } finally {
      setIsLoading(false)
    }
  }

  const exportConversation = () => {
    const conversationData = {
      sessionId,
      messages: conversations,
      exportedAt: new Date().toISOString()
    }

    const blob = new Blob([JSON.stringify(conversationData, null, 2)], {
      type: 'application/json'
    })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `soc-chatbot-export-${sessionId}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="flex flex-col h-[calc(100vh-200px)] bg-gray-800 rounded-lg shadow-lg">
      {/* Header de la conversation */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
        <div className="flex items-center space-x-3">
          <Bot className="h-6 w-6 text-blue-400" />
          <h2 className="text-lg font-semibold text-white">Assistant SOC</h2>
        </div>
        <button
          onClick={exportConversation}
          className="flex items-center space-x-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 rounded-md transition-colors"
        >
          <Download className="h-4 w-4" />
          <span className="text-sm">Exporter</span>
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4 chat-container">
        {conversations.length === 0 ? (
          <div className="text-center text-gray-400 py-12">
            <Bot className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>Bonjour ! Posez-moi une question sur votre sécurité.</p>
            <p className="text-sm mt-2">Ex: "Quelles sont les alertes critiques ?"</p>
          </div>
        ) : (
          conversations.map((message, index) => (
            <div
              key={index}
              className={`flex space-x-3 ${
                message.type === 'user' ? 'justify-end' : 'justify-start'
              }`}
            >
              {message.type === 'bot' && (
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                    <Bot className="h-5 w-5 text-white" />
                  </div>
                </div>
              )}
              
              <div
                className={`max-w-3xl rounded-lg p-4 ${
                  message.type === 'user'
                    ? 'bg-blue-600 text-white'
                    : message.isCritical
                    ? 'bg-red-600/20 border border-red-600 text-white'
                    : message.isError
                    ? 'bg-red-500/20 border border-red-500 text-white'
                    : 'bg-gray-700 text-white'
                }`}
              >
                {message.type === 'bot' && message.isCritical && (
                  <div className="flex items-center space-x-2 mb-2 text-red-400">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="text-sm font-medium">ALERTE CRITIQUE</span>
                  </div>
                )}
                
                {message.type === 'bot' ? (
                  <div className="prose prose-invert max-w-none" style={{ wordBreak: 'break-all', overflowWrap: 'break-word' }}>
                    <ReactMarkdown>{message.content}</ReactMarkdown>
                  </div>
                ) : (
                  <p>{message.content}</p>
                )}
                
                <div className="text-xs opacity-70 mt-2">
                  {new Date(message.timestamp).toLocaleTimeString()}
                  {message.responseTime && ` • ${message.responseTime}ms`}
                </div>
              </div>

              {message.type === 'user' && (
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                    <User className="h-5 w-5 text-white" />
                  </div>
                </div>
              )}
            </div>
          ))
        )}
        
        {isLoading && (
          <div className="flex space-x-3">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                <Bot className="h-5 w-5 text-white" />
              </div>
            </div>
            <div className="bg-gray-700 rounded-lg p-4 max-w-3xl">
              <div className="flex space-x-2">
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{animationDelay: '0.1s'}}></div>
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
              </div>
            </div>
          </div>
        )}
        
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <form onSubmit={handleSendMessage} className="p-4 border-t border-gray-700">
        <div className="flex space-x-3">
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder="Posez votre question sur la sécurité..."
            className="flex-1 px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={isLoading || !inputMessage.trim()}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg transition-colors flex items-center space-x-2"
          >
            <Send className="h-5 w-5" />
            <span>Envoyer</span>
          </button>
        </div>
      </form>
    </div>
  )
}

export default ChatInterface