import React from 'react'
import { BarChart3, AlertTriangle, Users, Clock } from 'lucide-react'

const Dashboard = ({ data }) => {
  if (!data) {
    return (
      <div className="text-center py-12 text-gray-400">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400 mx-auto mb-4"></div>
        <p>Chargement des données du dashboard...</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Questions totales</p>
              <p className="text-2xl font-bold text-white">{data.stats.total_questions}</p>
            </div>
            <BarChart3 className="h-8 w-8 text-blue-400" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Alertes critiques</p>
              <p className="text-2xl font-bold text-red-400">{data.stats.critical_questions}</p>
            </div>
            <AlertTriangle className="h-8 w-8 text-red-400" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Temps moyen réponse</p>
              <p className="text-2xl font-bold text-white">{data.stats.avg_response_time}ms</p>
            </div>
            <Clock className="h-8 w-8 text-green-400" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Utilisateurs actifs</p>
              <p className="text-2xl font-bold text-white">{data.top_users.length}</p>
            </div>
            <Users className="h-8 w-8 text-yellow-400" />
          </div>
        </div>
      </div>

      {/* System Summary */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">État du système Wazuh</h3>
        <div className="bg-gray-900 rounded-md p-4">
          <pre className="text-sm text-gray-300 whitespace-pre-wrap">
            {data.system_summary}
          </pre>
        </div>
      </div>

      {/* Top Users */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Utilisateurs les plus actifs</h3>
        <div className="space-y-3">
          {data.top_users.map((user, index) => (
            <div key={index} className="flex justify-between items-center py-2 border-b border-gray-700 last:border-b-0">
              <span className="text-gray-300">{user.name}</span>
              <span className="text-blue-400 font-medium">{user.count} questions</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default Dashboard