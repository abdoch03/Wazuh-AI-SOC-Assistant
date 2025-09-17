import os
import sqlite3
import hashlib
import json
import uuid
from datetime import datetime, timedelta
import traceback

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

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

# Initialisation de l'application Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-secret-key-for-dev')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Configuration CORS pour autoriser les requêtes depuis le frontend
CORS(app, origins=[
    "http://localhost:3000",      # Frontend en développement local
    "http://frontend:3000",       # Frontend en conteneur Docker
    "http://127.0.0.1:3000"       # Alternative pour le développement local
], supports_credentials=True)

# Configuration Flask-Login pour la gestion des sessions utilisateur
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # La vue de connexion si l'utilisateur n'est pas authentifié

# Chemin de la base de données SQLite pour l'authentification et l'historique
DB_PATH = '/app/database_data/soc_chatbot.db'

class User(UserMixin):
    """
    Représente un utilisateur du système pour Flask-Login.
    Contient l'ID, le nom d'utilisateur, le nom complet et le rôle de l'utilisateur.
    """
    def __init__(self, id, username, full_name, role):
        self.id = id
        self.username = username
        self.full_name = full_name
        self.role = role
    
    def get_id(self):
        """
        Retourne l'identifiant unique de l'utilisateur sous forme de chaîne.
        Requis par Flask-Login.
        """
        return str(self.id)
    
    def __repr__(self):
        """
        Représentation textuelle de l'objet User.
        """
        return f'<User {self.username}>'

def init_database():
    """
    Initialise la base de données SQLite et crée les tables nécessaires
    (users, conversations, user_limits) si elles n'existent pas.
    Crée également des utilisateurs par défaut (admin et analyste).
    """
    # Assure que le répertoire pour la base de données existe
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    
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
    
    # Vérifie et ajoute les colonnes manquantes à la table 'conversations' si nécessaire
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
        print(f"⚠️ Note lors de la vérification des colonnes: {e}")
    
    # Création de l'utilisateur admin par défaut
    admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
    conn.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, full_name, role) 
        VALUES ('admin', ?, 'Administrateur SOC', 'admin')
    ''', (admin_password,))
    
    # Création de l'utilisateur analyste par défaut
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
    """
    Charge un utilisateur à partir de son ID.
    Utilisé par Flask-Login pour récupérer l'objet utilisateur à partir de la session.
    """
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
        print(f"❌ Erreur lors du chargement de l'utilisateur {user_id}: {e}")
        return None

def get_user_limits(user_id):
    """
    Récupère les limites de traitement personnalisées pour un utilisateur donné.
    Si aucune limite personnalisée n'est définie, retourne des limites par défaut
    basées sur le rôle de l'utilisateur.
    """
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
        # Limites par défaut selon le rôle de l'utilisateur courant
        # Assurez-vous que current_user est disponible dans le contexte de l'appel
        if hasattr(current_user, 'role') and current_user.role == 'admin':
            return {'max_query_results': 100, 'gemini_max_rag_docs': 5}
        else:
            return {'max_query_results': 50, 'gemini_max_rag_docs': 3}

@app.route('/api/login', methods=['POST'])
def login():
    """
    Gère la connexion des utilisateurs.
    Valide les identifiants et établit la session Flask-Login.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Données JSON requises pour la connexion'}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'error': 'Nom d\'utilisateur et mot de passe requis'}), 400
        
        # Hachage du mot de passe pour vérification
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect(DB_PATH)
        user_data = conn.execute(
            'SELECT id, username, full_name, role FROM users WHERE username = ? AND password_hash = ?',
            (username, password_hash)
        ).fetchone()
        
        if user_data:
            # Met à jour le champ last_login
            conn.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                (user_data[0],)
            )
            conn.commit()
            
            user = User(user_data[0], user_data[1], user_data[2], user_data[3])
            login_user(user, remember=True) # Maintient la session active
            
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
        print(f"❌ Tentative de connexion échouée pour l'utilisateur: {username}")
        return jsonify({'error': 'Nom d\'utilisateur ou mot de passe incorrect'}), 401
        
    except Exception as e:
        # Enregistre la trace complète de l'erreur pour le débogage
        app.logger.error(f"Erreur dans la route /api/login: {traceback.format_exc()}")
        return jsonify({'error': 'Erreur interne du serveur lors de la connexion'}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """
    Déconnecte l'utilisateur courant et met fin à sa session.
    Nécessite une authentification préalable.
    """
    logout_user()
    print("🗑️ Déconnexion réussie.")
    return jsonify({'success': True})

@app.route('/api/user', methods=['GET'])
@login_required
def get_current_user():
    """
    Retourne les informations de l'utilisateur actuellement connecté.
    Nécessite une authentification préalable.
    """
    try:
        return jsonify({
            'id': current_user.id,
            'username': current_user.username,
            'full_name': current_user.full_name,
            'role': current_user.role,
            'is_authenticated': current_user.is_authenticated
        })
    except Exception as e:
        app.logger.error(f"Erreur lors de la récupération des informations utilisateur: {traceback.format_exc()}")
        return jsonify({'error': 'Erreur lors de la récupération des données utilisateur'}), 500

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    """
    Traite les requêtes de chat de l'utilisateur, interagit avec le système hybride
    (MongoDB, RAG, Gemini) et retourne une réponse.
    Enregistre la conversation dans l'historique.
    """
    data = request.get_json()
    question = data.get('question', '').strip()
    session_id = data.get('session_id') or str(uuid.uuid4())
    priority = data.get('priority', 'normal') # 'normal' ou 'urgent'
    
    if not question:
        return jsonify({'error': 'Question requise pour le chat'}), 400
    
    try:
        user_limits = get_user_limits(current_user.id)
        
        # Ajuste les limites de traitement en fonction de la priorité de la requête
        if priority == 'urgent':
            print(f"🚨 Requête URGENTE de {current_user.username} (Session: {session_id[:8]}...)")
            custom_limits = {
                **user_limits,
                'gemini_max_mongodb_results': 10,
                'gemini_max_rag_docs': 5
            }
        else:
            custom_limits = user_limits
        
        print(f"⚙️ Limites appliquées pour {current_user.username} (Rôle: {current_user.role}): {custom_limits}")
        
        # Applique les limites dynamiquement au système hybride avant le traitement
        set_processing_limits(**custom_limits)
        
        start_time = datetime.now()
        print(f"🔍 Traitement de la question: {question[:100]}... (Session: {session_id[:8]}...)")
        
        response = process_question(question, custom_limits, session_id)
        
        end_time = datetime.now()
        response_time_ms = int((end_time - start_time).total_seconds() * 1000)
        
        # Calcule la taille approximative du prompt pour le monitoring
        prompt_size = len(question) + len(response)
        
        query_type = "general"
        is_critical = False
        
        response_lower = response.lower()
        question_lower = question.lower()
        
        # Détection du type de requête basée sur des mots-clés
        if any(word in question_lower for word in ["total", "combien", "nombre"]):
            query_type = "count"
        elif any(word in question_lower for word in ["ssh", "connexion", "authentification"]):
            query_type = "authentication_analysis" 
        elif any(word in question_lower for word in ["critique", "critical", "urgent"]):
            query_type = "critical_alerts"
        elif any(word in question_lower for word in ["agent", "endpoint"]):
            query_type = "agent_status"
        elif any(word in question_lower for word in ["dernière", "récent", "historique"]):
            query_type = "recent_activity"
        elif any(word in question_lower for word in ["vulnérabilité", "cve"]):
            query_type = "vulnerability_scan"
        elif any(word in question_lower for word in ["fichier", "fim", "intégrité"]):
            query_type = "fim_changes"
        elif any(word in question_lower for word in ["malware", "virus", "rootkit"]):
            query_type = "malware_detection"

        # Détection de la criticité de la réponse
        is_critical = any(keyword in response_lower for keyword in [
            'critique', 'critical', 'urgent', 'niveau 13', 'niveau 14', 'niveau 15',
            'compromis', 'malware', 'breach', 'attack', 'intrusion', 'suspicious'
        ])
        
        # Sauvegarde la conversation dans la base de données
        conn = sqlite3.connect(DB_PATH)
        conn.execute('''
            INSERT INTO conversations (session_id, user_id, question, response, 
                                     response_time_ms, is_critical, query_type, prompt_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, current_user.id, question, response, response_time_ms, 
              is_critical, query_type, prompt_size))
        conn.commit()
        conn.close()
        
        app.logger.info(f"✅ Réponse générée en {response_time_ms}ms pour '{question[:50]}...'")
        app.logger.info(f"📏 Taille prompt: ~{prompt_size} chars, Type: {query_type}, Critique: {is_critical}")
        
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
        app.logger.error(f"❌ Erreur dans la route /api/chat pour la question '{question[:50]}...': {error_trace}")
        
        # Tente de sauvegarder l'erreur dans l'historique
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute('''
                INSERT INTO conversations (session_id, user_id, question, response, 
                                         response_time_ms, query_type, is_critical)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (session_id, current_user.id, question, f"ERREUR: {str(e)}", 
                  0, "error", True)) # Marque l'erreur comme critique
            conn.commit()
            conn.close()
        except Exception as db_err:
            app.logger.error(f"❌ Impossible de sauvegarder l'erreur dans la DB: {db_err}")
        
        return jsonify({
            'error': f'Erreur lors du traitement de votre question. Message: {str(e)}',
            'details': 'Vérifiez les logs du serveur pour plus de détails.'
        }), 500

@app.route('/api/dashboard', methods=['GET'])
@login_required
def dashboard():
    """
    Retourne les données agrégées pour le tableau de bord SOC.
    Inclut un résumé du système, les comptages globaux, les statistiques de conversation
    et les questions récentes de l'utilisateur.
    """
    try:
        system_summary = get_mongodb_summary_compact()
        total_counts = get_total_counts()
        
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
        
        query_types = conn.execute('''
            SELECT query_type, COUNT(*) as count
            FROM conversations
            WHERE created_at >= ?
            GROUP BY query_type
            ORDER BY count DESC
        ''', (yesterday.strftime('%Y-%m-%d %H:%M:%S'),)).fetchall()
        
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
        
        recent_questions = conn.execute('''
            SELECT question, query_type, is_critical, response_time_ms, created_at
            FROM conversations
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 10
        ''', (current_user.id,)).fetchall()
        
        conn.close()
        
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
        app.logger.error(f"❌ Erreur dans la route /api/dashboard: {traceback.format_exc()}")
        return jsonify({'error': f'Erreur lors du chargement du tableau de bord: {str(e)}'}), 500

@app.route('/api/history', methods=['GET'])
@login_required
def get_history():
    """
    Récupère l'historique des conversations pour l'utilisateur courant,
    avec des options de pagination, recherche et filtrage par type de requête/criticité.
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search_term = request.args.get('search', '')
        query_type_filter = request.args.get('query_type', '')
        critical_only = request.args.get('critical_only', False, type=bool)
        
        conn = sqlite3.connect(DB_PATH)
        
        where_clause = "WHERE 1=1"
        params = []
        
        # Les administrateurs peuvent voir toutes les conversations
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
        
        # Compte le nombre total de conversations pour la pagination
        total = conn.execute(f'''
            SELECT COUNT(*) FROM conversations c {where_clause}
        ''', params).fetchone()[0]
        
        # Récupère les conversations paginées
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
        
        # Récupère les types de requêtes disponibles pour le filtre
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
        app.logger.error(f"❌ Erreur dans la route /api/history: {traceback.format_exc()}")
        return jsonify({'error': f'Erreur lors du chargement de l\'historique: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
@login_required
def health_check():
    """
    Effectue une vérification de l'état de santé du backend et de ses composants critiques.
    Teste la connectivité à MongoDB et renvoie l'état des services.
    """
    try:
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'status': 'healthy',
            'components': {}
        }
        
        # Test de connectivité MongoDB
        try:
            db.command('ping') # Tente d'envoyer une commande ping à la base de données
            alerts_count = db["alerts"].count_documents({}) # Compte les documents pour vérifier l'accès
            health_status['components']['mongodb'] = {
                'status': 'healthy',
                'alerts_count': alerts_count
            }
        except Exception as e:
            health_status['components']['mongodb'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_status['status'] = 'degraded' # Dégrade l'état global si MongoDB échoue
        
        # Ajoute la configuration actuelle du système (limites de traitement)
        health_status['configuration'] = get_current_limits()
        
        return jsonify(health_status)
        
    except Exception as e:
        app.logger.error(f"❌ Erreur lors de la vérification de santé: {traceback.format_exc()}")
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'status': 'unhealthy',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # Initialisation de la base de données SQLite
    init_database()
    # Validation des dépendances et du système hybride (MongoDB, Gemini, ChromaDB)
    validate_system()
    # Chargement du re-ranker pour la pertinence des résultats RAG
    load_reranker()

    print("🚀 === SERVEUR FLASK OPTIMISÉ DÉMARRÉ ===")
    print("🌐 URL: http://localhost:5000")
    print("👤 Comptes par défaut:")
    print("   🔑 Admin: admin / admin123")
    print("   📊 Analyste: analyst / analyst123")
    print(" ")
    print("🔧 Fonctionnalités optimisées:")
    print("   ⚡ Traitement hybride avec limites intelligentes")
    print("   📊 Dashboard enrichi avec métriques de performance")
    print("   🎯 Classification automatique des requêtes")
    print("   📈 Statistiques avancées et monitoring")
    print("   ⚙️ Configuration dynamique des limites (admin)")
    
    app.run(debug=True, host='0.0.0.0', port=5000)