from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
import uuid
import os
import traceback


from wazuh_hybrid_system import (
    process_question,   
    get_mongodb_summary_compact,
    get_total_counts,
    set_processing_limits,
    get_current_limits,
    db,
    validate_system,
    load_reranker
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-secret-key-for-dev')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)


CORS(app, origins=[
    "http://localhost:3000",      # Dev local
    "http://frontend:3000",       # Docker interne
    "http://127.0.0.1:3000"       # Alternative locale
], supports_credentials=True)

# Configuration Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Base de données pour l'authentification et l'historique
DB_PATH = '/app/database_data/soc_chatbot.db'

# ========== CLASSE USER CORRIGÉE ==========
class User(UserMixin):
    """Classe utilisateur pour Flask-Login"""
    def __init__(self, id, username, full_name, role):
        self.id = id
        self.username = username
        self.full_name = full_name
        self.role = role
    
    def get_id(self):
        """Retourne l'ID utilisateur comme string pour Flask-Login"""
        return str(self.id)
    
    def __repr__(self):
        return f'<User {self.username}>'

# ========== FONCTIONS DE BASE DE DONNÉES ==========
def init_database():
    """Initialise la base de données SQLite avec le schéma complet"""
    # Assurer que le répertoire de la base de données existe
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    
    # Table utilisateurs
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            role TEXT DEFAULT 'analyst',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Table conversations avec TOUTES les colonnes nécessaires
    conn.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            user_id INTEGER,
            question TEXT NOT NULL,
            response TEXT NOT NULL,
            response_time_ms INTEGER DEFAULT 0,
            is_critical BOOLEAN DEFAULT 0,
            query_type TEXT DEFAULT 'general',
            prompt_size INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Table pour les limites de performance par utilisateur
    conn.execute('''
        CREATE TABLE IF NOT EXISTS user_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            max_query_results INTEGER DEFAULT 50,
            max_rag_docs INTEGER DEFAULT 3,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Vérifier et ajouter les colonnes manquantes si la table existe déjà
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA table_info(conversations)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        
        required_columns = {
            'query_type': 'TEXT DEFAULT "general"',
            'prompt_size': 'INTEGER DEFAULT 0',
            'response_time_ms': 'INTEGER DEFAULT 0',
            'is_critical': 'BOOLEAN DEFAULT 0'
        }
        
        for column_name, column_def in required_columns.items():
            if column_name not in existing_columns:
                print(f"➕ Ajout de la colonne manquante: {column_name}")
                cursor.execute(f"ALTER TABLE conversations ADD COLUMN {column_name} {column_def}")
        
    except sqlite3.OperationalError as e:
        print(f"⚠️ Note: {e}")
    
    # Créer un utilisateur admin par défaut
    admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
    conn.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, full_name, role) 
        VALUES ('admin', ?, 'Administrateur SOC', 'admin')
    ''', (admin_password,))
    
    # Créer un analyste par défaut
    analyst_password = hashlib.sha256('analyst123'.encode()).hexdigest()
    conn.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, full_name, role) 
        VALUES ('analyst', ?, 'Analyste SOC', 'analyst')
    ''', (analyst_password,))
    
    conn.commit()
    conn.close()
    print("✅ Base de données initialisée avec le schéma complet")

@login_manager.user_loader
def load_user(user_id):
    """Charge un utilisateur par son ID pour Flask-Login"""
    try:
        conn = sqlite3.connect(DB_PATH)
        user_data = conn.execute(
            'SELECT id, username, full_name, role FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        conn.close()
        
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3])
        return None
        
    except Exception as e:
        print(f"❌ Erreur load_user: {e}")
        return None

def get_user_limits(user_id):
    """Récupère les limites personnalisées pour un utilisateur"""
    conn = sqlite3.connect(DB_PATH)
    limits = conn.execute(
        'SELECT max_query_results, max_rag_docs FROM user_limits WHERE user_id = ?',
        (user_id,)
    ).fetchone()
    conn.close()
    
    if limits:
        return {
            'max_query_results': limits[0],
            'gemini_max_rag_docs': limits[1]
        }
    else:
        # Limites par défaut selon le rôle
        if hasattr(current_user, 'role') and current_user.role == 'admin':
            return {'max_query_results': 100, 'gemini_max_rag_docs': 5}
        else:
            return {'max_query_results': 50, 'gemini_max_rag_docs': 3}

# ========== ROUTES D'AUTHENTIFICATION ==========

@app.route('/api/login', methods=['POST'])
def login():
    """Route de connexion avec gestion d'erreur améliorée"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Données JSON requises'}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'error': 'Nom d\'utilisateur et mot de passe requis'}), 400
        
        # Hachage du mot de passe
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Recherche de l'utilisateur
        conn = sqlite3.connect(DB_PATH)
        user_data = conn.execute(
            'SELECT id, username, full_name, role FROM users WHERE username = ? AND password_hash = ?',
            (username, password_hash)
        ).fetchone()
        
        if user_data:
            # Mettre à jour la dernière connexion
            conn.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                (user_data[0],)
            )
            conn.commit()
            
            # Créer l'objet utilisateur
            user = User(user_data[0], user_data[1], user_data[2], user_data[3])
            login_user(user, remember=True)
            
            conn.close()
            
            print(f"✅ Connexion réussie pour {username} (rôle: {user_data[3]})")
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'full_name': user.full_name,
                    'role': user.role
                }
            })
        
        conn.close()
        print(f"❌ Tentative de connexion échouée pour {username}")
        return jsonify({'error': 'Nom d\'utilisateur ou mot de passe incorrect'}), 401
        
    except Exception as e:
        print(f"❌ Erreur dans login: {e}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})

@app.route('/api/user', methods=['GET'])
@login_required
def get_current_user():
    """Récupère les informations de l'utilisateur courant"""
    try:
        return jsonify({
            'id': current_user.id,
            'username': current_user.username,
            'full_name': current_user.full_name,
            'role': current_user.role,
            'is_authenticated': current_user.is_authenticated
        })
    except Exception as e:
        print(f"❌ Erreur get_current_user: {e}")
        return jsonify({'error': 'Erreur lors de la récupération des données utilisateur'}), 500

# ========== ROUTES PRINCIPALES ==========

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json()
    question = data.get('question', '').strip()
    session_id = data.get('session_id') or str(uuid.uuid4())
    priority = data.get('priority', 'normal')  # normal, urgent
    
    if not question:
        return jsonify({'error': 'Question requise'}), 400
    
    try:
        # Configuration des limites selon l'utilisateur et la priorité
        user_limits = get_user_limits(current_user.id)
        
        # Ajustement selon la priorité de la requête
        if priority == 'urgent':
            print(f"🚨 Requête URGENTE de {current_user.username}")
            custom_limits = {
                **user_limits,
                'gemini_max_mongodb_results': 10,
                'gemini_max_rag_docs': 5
            }
        else:
            custom_limits = user_limits
        
        print(f"⚙️ Limites appliquées pour {current_user.username}: {custom_limits}")
        
        # Appliquer les limites avant traitement
        set_processing_limits(**custom_limits)
        
        # Traitement avec la version OPTIMISÉE
        start_time = datetime.now()
        print(f"🔍 Traitement de la question: {question[:100]}...")
        
        response = process_question(question, custom_limits)
        
        end_time = datetime.now()
        response_time_ms = int((end_time - start_time).total_seconds() * 1000)
        
        # Calculer la taille approximative du prompt (pour monitoring)
        prompt_size = len(question) + len(response)
        
        # Détecter le type de requête et si c'est critique
        query_type = "general"
        is_critical = False
        
        # Analyse du contenu de la réponse pour classification
        response_lower = response.lower()
        question_lower = question.lower()
        
        # Détection du type de requête
        if any(word in question_lower for word in ["total", "combien", "nombre"]):
            query_type = "count"
        elif any(word in question_lower for word in ["ssh", "connexion"]):
            query_type = "ssh_analysis" 
        elif any(word in question_lower for word in ["critique", "critical"]):
            query_type = "critical_alerts"
        elif any(word in question_lower for word in ["agent"]):
            query_type = "agent_status"
        elif any(word in question_lower for word in ["dernière", "récent"]):
            query_type = "recent_activity"
        
        # Détection de criticité
        is_critical = any(keyword in response_lower for keyword in [
            'critique', 'critical', 'urgent', 'niveau 13', 'niveau 14', 'niveau 15',
            'compromis', 'malware', 'breach', 'attack', 'intrusion', 'suspicious'
        ])
        
        # Sauvegarder dans l'historique avec métadonnées enrichies
        conn = sqlite3.connect(DB_PATH)
        conn.execute('''
            INSERT INTO conversations (session_id, user_id, question, response, 
                                     response_time_ms, is_critical, query_type, prompt_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, current_user.id, question, response, response_time_ms, 
              is_critical, query_type, prompt_size))
        conn.commit()
        conn.close()
        
        # Logging amélioré
        print(f"✅ Réponse générée en {response_time_ms}ms")
        print(f"📏 Taille prompt: ~{prompt_size} chars")
        print(f"🏷️ Type: {query_type}, Critique: {is_critical}")
        
        return jsonify({
            'response': response,
            'session_id': session_id,
            'is_critical': is_critical,
            'query_type': query_type,
            'response_time_ms': response_time_ms,
            'timestamp': end_time.isoformat(),
            'metadata': {
                'prompt_size': prompt_size,
                'limits_applied': custom_limits,
                'priority': priority
            }
        })
        
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"❌ Erreur dans /api/chat: {error_trace}")
        
        # Sauvegarder l'erreur pour analyse
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute('''
                INSERT INTO conversations (session_id, user_id, question, response, 
                                         response_time_ms, query_type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session_id, current_user.id, question, f"ERREUR: {str(e)}", 
                  0, "error"))
            conn.commit()
            conn.close()
        except:
            pass  # Si on ne peut pas sauvegarder l'erreur, on continue
        
        return jsonify({
            'error': f'Erreur lors du traitement: {str(e)}',
            'details': 'Vérifiez les logs serveur pour plus de détails'
        }), 500

@app.route('/api/dashboard', methods=['GET'])
@login_required
def dashboard():
    """Dashboard amélioré avec statistiques optimisées"""
    try:
        # Statistiques MongoDB (version compacte)
        print("🔧 Récupération du résumé système compact...")
        system_summary = get_mongodb_summary_compact()
        
        # Comptages totaux pour affichage
        total_counts = get_total_counts()
        
        # Statistiques conversations (dernières 24h)
        conn = sqlite3.connect(DB_PATH)
        yesterday = datetime.now() - timedelta(days=1)
        
        stats = conn.execute('''
            SELECT 
                COUNT(*) as total_questions,
                COUNT(CASE WHEN is_critical = 1 THEN 1 END) as critical_questions,
                AVG(response_time_ms) as avg_response_time,
                AVG(prompt_size) as avg_prompt_size,
                COUNT(DISTINCT user_id) as active_users
            FROM conversations 
            WHERE created_at >= ?
        ''', (yesterday.strftime('%Y-%m-%d %H:%M:%S'),)).fetchone()
        
        # Distribution par type de requête
        query_types = conn.execute('''
            SELECT query_type, COUNT(*) as count
            FROM conversations
            WHERE created_at >= ?
            GROUP BY query_type
            ORDER BY count DESC
        ''', (yesterday.strftime('%Y-%m-%d %H:%M:%S'),)).fetchall()
        
        # Top utilisateurs actifs
        top_users = conn.execute('''
            SELECT u.full_name, u.role, COUNT(*) as question_count,
                   AVG(c.response_time_ms) as avg_response_time
            FROM conversations c
            JOIN users u ON c.user_id = u.id
            WHERE c.created_at >= ?
            GROUP BY c.user_id
            ORDER BY question_count DESC
            LIMIT 5
        ''', (yesterday.strftime('%Y-%m-%d %H:%M:%S'),)).fetchall()
        
        # Questions récentes de l'utilisateur actuel
        recent_questions = conn.execute('''
            SELECT question, query_type, is_critical, response_time_ms, created_at
            FROM conversations
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 10
        ''', (current_user.id,)).fetchall()
        
        conn.close()
        
        # Performance du système
        current_limits = get_current_limits()
        
        return jsonify({
            'system_summary': system_summary,
            'total_counts': {
                'alerts': total_counts.get('total_alerts', 0),
                'agents': total_counts.get('total_agents', 0),
                'active_agents': total_counts.get('active_agents', 0)
            },
            'stats': {
                'total_questions': stats[0] or 0,
                'critical_questions': stats[1] or 0,
                'avg_response_time': round(stats[2] or 0, 2),
                'avg_prompt_size': round(stats[3] or 0, 0),
                'active_users': stats[4] or 0
            },
            'query_distribution': [
                {'type': qt[0] or 'unknown', 'count': qt[1]} 
                for qt in query_types
            ],
            'top_users': [{
                'name': user[0], 
                'role': user[1],
                'count': user[2],
                'avg_time': round(user[3] or 0, 2)
            } for user in top_users],
            'recent_questions': [{
                'question': q[0][:100] + '...' if len(q[0]) > 100 else q[0],
                'type': q[1] or 'general',
                'is_critical': bool(q[2]),
                'response_time': q[3] or 0,
                'timestamp': q[4]
            } for q in recent_questions],
            'system_config': {
                'current_limits': current_limits,
                'user_role': current_user.role
            }
        })
        
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"❌ Erreur dashboard: {error_trace}")
        return jsonify({'error': f'Erreur dashboard: {str(e)}'}), 500

@app.route('/api/history', methods=['GET'])
@login_required
def get_history():
    """Historique amélioré avec filtres par type de requête"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search_term = request.args.get('search', '')
        query_type_filter = request.args.get('query_type', '')
        critical_only = request.args.get('critical_only', False, type=bool)
        
        conn = sqlite3.connect(DB_PATH)
        
        # Construire la requête avec filtres
        where_clause = "WHERE 1=1"
        params = []
        
        if current_user.role != 'admin':
            where_clause += " AND c.user_id = ?"
            params.append(current_user.id)
        
        if search_term:
            where_clause += " AND (c.question LIKE ? OR c.response LIKE ?)"
            params.extend([f'%{search_term}%', f'%{search_term}%'])
        
        if query_type_filter:
            where_clause += " AND c.query_type = ?"
            params.append(query_type_filter)
        
        if critical_only:
            where_clause += " AND c.is_critical = 1"
        
        # Compter le total
        total = conn.execute(f'''
            SELECT COUNT(*) FROM conversations c {where_clause}
        ''', params).fetchone()[0]
        
        # Récupérer les conversations paginées
        offset = (page - 1) * per_page
        conversations = conn.execute(f'''
            SELECT c.id, c.question, c.response, c.is_critical, c.created_at, 
                   c.response_time_ms, c.query_type, c.prompt_size, u.full_name
            FROM conversations c
            JOIN users u ON c.user_id = u.id
            {where_clause}
            ORDER BY c.created_at DESC
            LIMIT ? OFFSET ?
        ''', params + [per_page, offset]).fetchall()
        
        # Types de requête disponibles pour le filtre
        available_types = conn.execute('''
            SELECT DISTINCT query_type, COUNT(*) as count
            FROM conversations c
            WHERE query_type IS NOT NULL
            GROUP BY query_type
            ORDER BY count DESC
        ''').fetchall()
        
        conn.close()
        
        return jsonify({
            'conversations': [{
                'id': conv[0],
                'question': conv[1],
                'response': conv[2][:500] + '...' if len(conv[2]) > 500 else conv[2],
                'is_critical': bool(conv[3]),
                'created_at': conv[4],
                'response_time_ms': conv[5],
                'query_type': conv[6] or 'general',
                'prompt_size': conv[7] or 0,
                'user_name': conv[8]
            } for conv in conversations],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            },
            'available_types': [
                {'type': type_info[0], 'count': type_info[1]}
                for type_info in available_types
            ]
        })
        
    except Exception as e:
        return jsonify({'error': f'Erreur historique: {str(e)}'}), 500

# ========== ROUTES SUPPLÉMENTAIRES ==========
# (Ajoutez ici les autres routes comme /api/config/limits, /api/export/conversation, etc.)

@app.route('/api/health', methods=['GET'])
@login_required
def health_check():
    """Vérification de l'état du système"""
    try:
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'status': 'healthy',
            'components': {}
        }
        
        # Test MongoDB
        try:
            db.command('ping')
            alerts_count = db["alerts"].count_documents({})
            health_status['components']['mongodb'] = {
                'status': 'healthy',
                'alerts_count': alerts_count
            }
        except Exception as e:
            health_status['components']['mongodb'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_status['status'] = 'degraded'
        
        # Configuration actuelle
        health_status['configuration'] = get_current_limits()
        
        return jsonify(health_status)
        
    except Exception as e:
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'status': 'unhealthy',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    init_database()
    validate_system()
    load_reranker()
    print("🚀 === SERVEUR FLASK OPTIMISÉ DÉMARRÉ ===")
    print("🌐 URL: http://localhost:5000")
    print("👤 Comptes par défaut:")
    print("   🔑 Admin: admin / admin123")
    print("   📊 Analyste: analyst / analyst123")
    print("")
    print("🔧 Fonctionnalités optimisées:")
    print("   ⚡ Traitement hybride avec limites intelligentes")
    print("   📊 Dashboard enrichi avec métriques de performance")
    print("   🎯 Classification automatique des requêtes")
    print("   📈 Statistiques avancées et monitoring")
    print("   ⚙️ Configuration dynamique des limites (admin)")
    
    app.run(debug=True, host='0.0.0.0', port=5000)