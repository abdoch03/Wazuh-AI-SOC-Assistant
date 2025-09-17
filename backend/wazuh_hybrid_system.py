import os
import requests
import json
import math
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from pymongo import MongoClient
import re

from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from sentence_transformers import CrossEncoder

# --- Configuration améliorée ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("❌ Erreur : La variable d'environnement GEMINI_API_KEY n'est pas définie.")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "wazuh_siem")
client = MongoClient(MONGO_URI)
db = client[MONGO_DB_NAME]

GEMINI_MODEL = "gemini-1.5-flash"
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"


CONFIG = {
    "max_recent_alerts": 1000,
    "max_query_results": 100,
    "rag_top_k": 10,
    "default_days_back": 7,
    "max_total_count_limit": 50000,
    "gemini_max_mongodb_results": 5,
    "gemini_max_rag_docs": 3,
    "gemini_max_chars_per_result": 300,
    "gemini_summary_max_chars": 800,
}

# --- Cache pour l'historique des conversations ---
conversation_history = {}

# --- Base vectorielle ---
embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
VECTOR_DB_DIR = "./data_collecte/chroma_db"
vectorstore = Chroma(
    collection_name="wazuh_data",
    embedding_function=embeddings,
    persist_directory=VECTOR_DB_DIR
)

# --- Re-ranker optionnel ---
RERANKER_AVAILABLE = False
reranker = None

# =============================================================================
# GESTIONNAIRE INTELLIGENT DES DONNÉES
# =============================================================================

class DataManager:
    """Gestionnaire intelligent des données avec pagination et compression"""
    
    def __init__(self, config: dict):
        self.config = config
        self.limits = {
            "critical": {"max_items": 20, "chars_per_item": 600},
            "detailed": {"max_items": 15, "chars_per_item": 500},
            "standard": {"max_items": 10, "chars_per_item": 400},
            "summary": {"max_items": 8, "chars_per_item": 300}
        }
        
    def estimate_token_usage(self, text: str) -> int:
        """Estime l'usage de tokens (approximation : 1 token = 4 caractères)"""
        return len(text) // 4
    
    def determine_detail_level(self, question: str, data_count: int) -> str:
        """Détermine le niveau de détail requis selon la question"""
        question_lower = question.lower()
        
        # Questions critiques nécessitant le maximum de détails
        critical_keywords = ["critique", "critical", "incident", "intrusion", "malware", "breach"]
        if any(kw in question_lower for kw in critical_keywords):
            return "critical"
        
        # Questions demandant explicitement des détails
        detail_keywords = ["détail", "detail", "complet", "full", "analyse", "investigation"]
        if any(kw in question_lower for kw in detail_keywords) or data_count <= 5:
            return "detailed"
        
        # Questions de résumé
        summary_keywords = ["résumé", "summary", "overview", "global", "général"]
        if any(kw in question_lower for kw in summary_keywords) or data_count > 50:
            return "summary"
            
        return "standard"
    
    def smart_truncate(self, text: str, max_chars: int) -> str:
        """Troncature intelligente préservant les informations importantes"""
        if len(text) <= max_chars:
            return text
            
        # Préserver les éléments importants (IPs, règles, timestamps)
        important_patterns = [
            r'\d+\.\d+\.\d+\.\d+',  # IPs
            r'rule[_\s]*\d+',       # Rule IDs
            r'level[_\s]*\d+',      # Levels
            r'\d{4}-\d{2}-\d{2}',   # Dates
            r'agent[_\s]*\d+',      # Agent IDs
        ]
        
        # Tronquer en gardant le début et la fin si possible
        if max_chars > 100:
            start_chars = int(max_chars * 0.7)
            end_chars = max_chars - start_chars - 3
            
            truncated = text[:start_chars] + "..." + text[-end_chars:]
            return truncated
        else:
            return text[:max_chars-3] + "..."
    
    def compress_data_item(self, item: Dict, max_chars: int, priority_fields: List[str] = None) -> str:
        """Compresse un élément de données en gardant les champs prioritaires"""
        if not priority_fields:
            priority_fields = ['timestamp', 'agent_id', 'level', 'rule_description', 'rule_id']
        
        # Construire la représentation avec priorités
        parts = []
        remaining_chars = max_chars
        
        for field in priority_fields:
            if field in item and remaining_chars > 0:
                value = str(item[field])
                if len(value) + len(field) + 3 <= remaining_chars:
                    parts.append(f"{field}: {value}")
                    remaining_chars -= len(parts[-1]) + 2
                else:
                    available = remaining_chars - len(field) - 5
                    if available > 10:
                        truncated_value = self.smart_truncate(value, available)
                        parts.append(f"{field}: {truncated_value}")
                    break
        
        # Ajouter d'autres champs si il reste de la place
        other_fields = [k for k in item.keys() if k not in priority_fields and k != '_id']
        for field in other_fields:
            if remaining_chars > len(field) + 10:
                value = str(item[field])
                available = min(remaining_chars - len(field) - 3, 50)
                if len(value) <= available:
                    parts.append(f"{field}: {value}")
                    remaining_chars -= len(parts[-1]) + 2
                else:
                    truncated_value = self.smart_truncate(value, available)
                    parts.append(f"{field}: {truncated_value}")
                    break
        
        return " | ".join(parts)
    
    def prepare_data(self, mongodb_data: List[Dict], query_type: str, question: str) -> str:
        """Prépare les données de manière intelligente selon le contexte"""
        if not mongodb_data:
            return "=== AUCUNE DONNÉE TROUVÉE ==="
        
        # Déterminer le niveau de détail requis
        detail_level = self.determine_detail_level(question, len(mongodb_data))
        limits = self.limits[detail_level]
        
        # Limiter le nombre d'éléments
        max_items = min(limits["max_items"], len(mongodb_data))
        selected_data = mongodb_data[:max_items]
        
        # Estimer l'espace disponible
        total_estimated_chars = limits["max_items"] * limits["chars_per_item"]
        
        # Préparer les données
        formatted_items = []
        current_total_chars = 0
        
        # Définir les champs prioritaires selon le type de requête
        priority_fields_map = {
            "ssh_failed": ['timestamp', 'srcip', 'agent_id', 'rule_description'],
            "critical_alerts": ['timestamp', 'level', 'agent_id', 'rule_description', 'rule_id'],
            "vulnerabilities": ['timestamp', 'agent_id', 'vulnerability', 'severity'],
            "fim_changes": ['timestamp', 'agent_id', 'syscheck', 'rule_description'],
            "network_activity": ['timestamp', 'srcip', 'dstip', 'agent_id', 'rule_description'],
            "default": ['timestamp', 'agent_id', 'level', 'rule_description', 'rule_id']
        }
        
        priority_fields = priority_fields_map.get(query_type, priority_fields_map["default"])
        
        for idx, item in enumerate(selected_data, 1):
            # Calculer l'espace disponible pour cet élément
            remaining_items = len(selected_data) - idx + 1
            avg_chars_per_remaining = (total_estimated_chars - current_total_chars) // remaining_items
            max_chars_this_item = min(limits["chars_per_item"], avg_chars_per_remaining)
            
            # Comprimer l'élément
            compressed_item = self.compress_data_item(item, max_chars_this_item, priority_fields)
            item_with_number = f"[{idx}] {compressed_item}"
            
            formatted_items.append(item_with_number)
            current_total_chars += len(item_with_number)
            
            # Vérifier si on approche de la limite
            estimated_tokens = self.estimate_token_usage("\n".join(formatted_items))
            if estimated_tokens > 1500:
                break
        
        # Assembler le résultat final
        header = f"=== {query_type.upper().replace('_', ' ')} - NIVEAU {detail_level.upper()} ==="
        summary = f"Affichage de {len(formatted_items)}/{len(mongodb_data)} éléments"
        
        if len(mongodb_data) > len(formatted_items):
            summary += f" (+ {len(mongodb_data) - len(formatted_items)} éléments supplémentaires disponibles)"
        
        result = f"{header}\n{summary}\n\n" + "\n\n".join(formatted_items)
        
        # Ajouter statistiques si pertinentes
        if len(mongodb_data) > 5:
            stats = self.generate_quick_stats(mongodb_data)
            result += f"\n\n=== STATISTIQUES RAPIDES ===\n{stats}"
        
        return result
    
    def generate_quick_stats(self, data: List[Dict]) -> str:
        """Génère des statistiques rapides sur le dataset"""
        stats = []
        
        # Compter par level si disponible
        if data and 'level' in data[0]:
            levels = {}
            for item in data:
                level = item.get('level', 'Unknown')
                levels[level] = levels.get(level, 0) + 1
            stats.append(f"Niveaux: {dict(sorted(levels.items(), reverse=True))}")
        
        # Compter par agent si disponible
        if data and 'agent_id' in data[0]:
            agents = {}
            for item in data:
                agent = item.get('agent_id', 'Unknown')
                agents[agent] = agents.get(agent, 0) + 1
            top_agents = sorted(agents.items(), key=lambda x: x[1], reverse=True)[:3]
            stats.append(f"Top Agents: {dict(top_agents)}")
        
        # Période couverte si timestamps disponibles
        if data and 'timestamp' in data[0]:
            timestamps = [item.get('timestamp') for item in data if item.get('timestamp')]
            if timestamps:
                stats.append(f"Période: {min(timestamps)} à {max(timestamps)}")
        
        return " | ".join(stats)

# Initialisation du gestionnaire
data_manager = DataManager(CONFIG)

class EnhancedDataFormatter:
    """Formateur de données spécialisé pour réponses structurées"""
    
    def __init__(self):
        self.formatters = {
            "high_alerts": self.format_high_alerts,
            "critical_alerts": self.format_critical_alerts,
            "ssh_failed": self.format_ssh_failures,
            "fim_changes": self.format_fim_changes,
            "vulnerabilities": self.format_vulnerabilities,
            "network_activity": self.format_network_activity,
            "authentication": self.format_authentication,
            "malware_detection": self.format_malware_detection,
            "general_search": self.format_general_data,
            "agent_status": self.format_agent_status,
            "disconnected_agents": self.format_disconnected_agents
        }
    
    def format_data(self, data: List[Dict], query_type: str, question: str) -> str:
        """Point d'entrée principal pour le formatage"""
        if not data:
            return "=== AUCUNE DONNÉE TROUVÉE ==="
        
        formatter = self.formatters.get(query_type, self.format_general_data)
        return formatter(data, question)
    
    def format_high_alerts(self, data: List[Dict], question: str) -> str:
        """Format spécialisé pour alertes de niveau élevé"""
        if not data:
            return "Aucune alerte de niveau élevé trouvée"
        
        # En-tête avec statistiques
        total_count = len(data)
        level_stats = {}
        agent_stats = {}
        
        for alert in data:
            level = alert.get('level', 'Unknown')
            agent = alert.get('agent_id', 'Unknown')
            level_stats[level] = level_stats.get(level, 0) + 1
            agent_stats[agent] = agent_stats.get(agent, 0) + 1
        
        result = f"""=== DONNÉES REÇUES - ALERTES NIVEAU ÉLEVÉ ===
Total trouvé: {total_count} alertes
Niveaux: {dict(sorted(level_stats.items(), reverse=True))}
Agents concernés: {len(agent_stats)}
Période: {data[-1].get('timestamp', 'N/A')} à {data[0].get('timestamp', 'N/A')}

=== DÉTAILS DES ALERTES ==="""
        
        # Limiter à 15 alertes pour lisibilité mais garder le maximum d'infos
        display_alerts = data[:15]
        
        for i, alert in enumerate(display_alerts, 1):
            timestamp = alert.get('timestamp', 'N/A')
            agent_id = alert.get('agent_id', 'N/A')
            agent_name = alert.get('agent_name', 'N/A')
            level = alert.get('level', 'N/A')
            rule_id = alert.get('rule_id', 'N/A')
            rule_desc = alert.get('rule_description', 'N/A')
            location = alert.get('location', 'N/A')
            
            # Extraire IP source si disponible
            srcip = alert.get('srcip', alert.get('data', {}).get('srcip', 'N/A'))
            
            # Log partiel pour contexte
            full_log = alert.get('full_log', '')
            log_preview = full_log[:150] + "..." if len(full_log) > 150 else full_log
            
            result += f"""

[{i}] ALERTE NIVEAU {level} - {timestamp}
├── Agent: {agent_id} ({agent_name})
├── Règle: {rule_id} - {rule_desc}
├── Localisation: {location}
├── IP Source: {srcip}
└── Log: {log_preview}"""
        
        if total_count > 15:
            result += f"\n\n... et {total_count - 15} autres alertes similaires"
        
        return result
    
    def format_critical_alerts(self, data: List[Dict], question: str) -> str:
        """Format spécialisé pour alertes critiques (niveau ≥13)"""
        
        return self.format_high_alerts(data, question).replace("NIVEAU ÉLEVÉ", "CRITIQUES (≥13)")
    
    def format_ssh_failures(self, data: List[Dict], question: str) -> str:
        """Format spécialisé pour échecs SSH"""
        if not data:
            return "Aucun échec SSH détecté"
        
        # Analyse des IPs et patterns
        ip_attempts = {}
        time_pattern = {}
        
        for attempt in data:
            srcip = attempt.get('srcip', 'IP_Inconnue')
            timestamp = attempt.get('timestamp', '')
            
            ip_attempts[srcip] = ip_attempts.get(srcip, 0) + 1
            
            # Extraire heure pour pattern temporel
            if timestamp:
                hour = timestamp.split('T')[1][:2] if 'T' in timestamp else 'Unknown'
                time_pattern[hour] = time_pattern.get(hour, 0) + 1
        
        # Top IPs suspectes
        top_ips = sorted(ip_attempts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        result = f"""=== DONNÉES REÇUES - ÉCHECS AUTHENTIFICATION SSH ===
Total tentatives: {len(data)}
IPs uniques: {len(ip_attempts)}
Top IPs suspectes: {dict(top_ips)}
Période: {data[-1].get('timestamp', 'N/A')} à {data[0].get('timestamp', 'N/A')}

=== DÉTAILS DES TENTATIVES ==="""
        
        # Afficher les 10 premiers échecs avec contexte
        for i, attempt in enumerate(data[:10], 1):
            timestamp = attempt.get('timestamp', 'N/A')
            agent_id = attempt.get('agent_id', 'N/A')
            agent_name = attempt.get('agent_name', 'N/A')
            srcip = attempt.get('srcip', 'IP_Inconnue')
            rule_desc = attempt.get('rule_description', 'N/A')
            location = attempt.get('location', 'N/A')
            
            # Extraire utilisateur depuis le log si disponible
            full_log = attempt.get('full_log', '')
            user_match = re.search(r'user (\w+)', full_log) or re.search(r'for (\w+)', full_log)
            user = user_match.group(1) if user_match else 'Unknown'
            
            result += f"""

[{i}] ÉCHEC SSH - {timestamp}
├── Agent: {agent_id} ({agent_name})
├── IP Source: {srcip} (Total: {ip_attempts.get(srcip, 1)} tentatives)
├── Utilisateur: {user}
├── Localisation: {location}
└── Règle: {rule_desc}"""
        
        if len(data) > 10:
            result += f"\n\n... et {len(data) - 10} autres tentatives"
        
        return result
    
    # Placeholder pour autres formatters
    def format_fim_changes(self, data: List[Dict], question: str) -> str:
        if not data:
            return "Aucune modification de fichier détectée"
        
        # Analyser les patterns de modifications
        file_changes = {}
        directories = set()
        change_types = {}
        
        for change in data:
            # Extraire chemin fichier
            syscheck = change.get('syscheck', {})
            file_path = syscheck.get('path', change.get('location', 'Fichier_inconnu'))
            
            # Analyser le type de changement
            if 'added' in str(change).lower():
                change_type = 'Ajouté'
            elif 'deleted' in str(change).lower() or 'removed' in str(change).lower():
                change_type = 'Supprimé'
            elif 'modified' in str(change).lower():
                change_type = 'Modifié'
            else:
                change_type = 'Changé'
            
            file_changes[file_path] = file_changes.get(file_path, 0) + 1
            change_types[change_type] = change_types.get(change_type, 0) + 1
            
            # Extraire répertoire
            if '/' in file_path:
                directory = '/'.join(file_path.split('/')[:-1])
                directories.add(directory)
        
        result = f"""=== DONNÉES REÇUES - MODIFICATIONS FICHIERS (FIM) ===
    Total modifications: {len(data)}
    Fichiers uniques: {len(file_changes)}
    Répertoires concernés: {len(directories)}
    Types de changements: {dict(change_types)}
    Période: {data[-1].get('timestamp', 'N/A')} à {data[0].get('timestamp', 'N/A')}

    === DÉTAILS DES MODIFICATIONS ==="""
        
        for i, change in enumerate(data[:12], 1):
            timestamp = change.get('timestamp', 'N/A')
            agent_id = change.get('agent_id', 'N/A')
            agent_name = change.get('agent_name', 'N/A')
            
            # Détails syscheck
            syscheck = change.get('syscheck', {})
            file_path = syscheck.get('path', 'Fichier_inconnu')
            size_before = syscheck.get('size_before', 'N/A')
            size_after = syscheck.get('size_after', 'N/A')
            md5_before = syscheck.get('md5_before', 'N/A')[:8] if syscheck.get('md5_before') else 'N/A'
            md5_after = syscheck.get('md5_after', 'N/A')[:8] if syscheck.get('md5_after') else 'N/A'
            
            rule_desc = change.get('rule_description', 'Modification fichier')
            
            result += f"""

    [{i}] MODIFICATION FIM - {timestamp}
    ├── Agent: {agent_id} ({agent_name})
    ├── Fichier: {file_path}
    ├── Taille: {size_before} → {size_after}
    ├── MD5: {md5_before} → {md5_after}
    └── Règle: {rule_desc}"""
        
        if len(data) > 12:
            result += f"\n\n... et {len(data) - 12} autres modifications"
        
        return result
    
    def format_vulnerabilities(self, data: List[Dict], question: str) -> str:
        if not data:
            return "Aucune vulnérabilité détectée"
        
        # Analyser les vulnérabilités
        cve_list = set()
        severity_stats = {}
        package_vulns = {}
        
        for vuln in data:
            vulnerability = vuln.get('vulnerability', {})
            
            # Extraire CVE
            cve = vulnerability.get('cve', vulnerability.get('id', 'CVE_inconnu'))
            if cve != 'CVE_inconnu':
                cve_list.add(cve)
            
            # Sévérité
            severity = vulnerability.get('severity', vulnerability.get('level', 'Unknown'))
            severity_stats[severity] = severity_stats.get(severity, 0) + 1
            
            # Package affecté
            package = vulnerability.get('package', {})
            pkg_name = package.get('name', 'Package_inconnu')
            if pkg_name != 'Package_inconnu':
                package_vulns[pkg_name] = package_vulns.get(pkg_name, 0) + 1
        
        result = f"""=== DONNÉES REÇUES - VULNÉRABILITÉS ===
    Total vulnérabilités: {len(data)}
    CVE uniques: {len(cve_list)}
    Sévérités: {dict(sorted(severity_stats.items()))}
    Packages concernés: {len(package_vulns)}
    Période: {data[-1].get('timestamp', 'N/A')} à {data[0].get('timestamp', 'N/A')}

    === DÉTAILS DES VULNÉRABILITÉS ==="""
        
        for i, vuln in enumerate(data[:10], 1):
            timestamp = vuln.get('timestamp', 'N/A')
            agent_id = vuln.get('agent_id', 'N/A')
            agent_name = vuln.get('agent_name', 'N/A')
            
            vulnerability = vuln.get('vulnerability', {})
            cve = vulnerability.get('cve', vulnerability.get('id', 'CVE_inconnu'))
            severity = vulnerability.get('severity', 'Unknown')
            score = vulnerability.get('cvss', {}).get('score', 'N/A')
            
            package = vulnerability.get('package', {})
            pkg_name = package.get('name', 'Package_inconnu')
            pkg_version = package.get('version', 'Version_inconnue')
            
            title = vulnerability.get('title', vuln.get('rule_description', 'Vulnérabilité détectée'))
            
            result += f"""

    [{i}] VULNÉRABILITÉ - {timestamp}
    ├── Agent: {agent_id} ({agent_name})
    ├── CVE: {cve} (Score: {score})
    ├── Sévérité: {severity}
    ├── Package: {pkg_name} v{pkg_version}
    └── Description: {title[:80]}..."""
        
        if len(data) > 10:
            result += f"\n\n... et {len(data) - 10} autres vulnérabilités"
        
        return result
    
    def format_network_activity(self, data: List[Dict], question: str) -> str:
        if not data:
            return "Aucune activité réseau détectée"
        
        # Analyser patterns réseau
        src_ips = set()
        dst_ips = set()
        ports = set()
        protocols = set()
        
        for activity in data:
            if activity.get('srcip'):
                src_ips.add(activity['srcip'])
            if activity.get('dstip'):
                dst_ips.add(activity['dstip'])
            if activity.get('srcport'):
                ports.add(activity['srcport'])
            if activity.get('dstport'):
                ports.add(activity['dstport'])
            if activity.get('protocol'):
                protocols.add(activity['protocol'])
        
        result = f"""=== DONNÉES REÇUES - ACTIVITÉ RÉSEAU ===
    Total événements: {len(data)}
    IPs sources: {len(src_ips)}
    IPs destinations: {len(dst_ips)}
    Ports uniques: {len(ports)}
    Protocoles: {list(protocols) if protocols else ['N/A']}
    Période: {data[-1].get('timestamp', 'N/A')} à {data[0].get('timestamp', 'N/A')}

    === DÉTAILS ACTIVITÉ RÉSEAU ==="""
        
        for i, activity in enumerate(data[:10], 1):
            timestamp = activity.get('timestamp', 'N/A')
            agent_id = activity.get('agent_id', 'N/A')
            agent_name = activity.get('agent_name', 'N/A')
            
            srcip = activity.get('srcip', 'N/A')
            dstip = activity.get('dstip', 'N/A')
            srcport = activity.get('srcport', 'N/A')
            dstport = activity.get('dstport', 'N/A')
            protocol = activity.get('protocol', 'N/A')
            
            rule_desc = activity.get('rule_description', 'Activité réseau')
            level = activity.get('level', 'N/A')
            
            result += f"""

    [{i}] ACTIVITÉ RÉSEAU L{level} - {timestamp}
    ├── Agent: {agent_id} ({agent_name})
    ├── Connexion: {srcip}:{srcport} → {dstip}:{dstport}
    ├── Protocole: {protocol}
    └── Règle: {rule_desc}"""
        
        if len(data) > 10:
            result += f"\n\n... et {len(data) - 10} autres événements réseau"
        
        return result

    def format_authentication(self, data: List[Dict], question: str) -> str:
        """Format pour événements d'authentification"""
        if not data:
            return "Aucun événement d'authentification détecté"
        
        # Analyser patterns d'authentification
        success_count = 0
        failure_count = 0
        users = set()
        src_ips = set()
        
        for auth in data:
            rule_desc = auth.get('rule_description', '').lower()
            full_log = auth.get('full_log', '').lower()
            
            if 'success' in rule_desc or 'successful' in rule_desc or 'accepted' in full_log:
                success_count += 1
            elif 'fail' in rule_desc or 'invalid' in rule_desc or 'denied' in full_log:
                failure_count += 1
            
            # Extraire utilisateur du log
            full_log_content = auth.get('full_log', '')
            user_patterns = [r'user (\w+)', r'for (\w+)', r'login (\w+)', r'user=(\w+)']
            for pattern in user_patterns:
                match = re.search(pattern, full_log_content)
                if match:
                    users.add(match.group(1))
                    break
            
            if auth.get('srcip'):
                src_ips.add(auth['srcip'])
        
        result = f"""=== DONNÉES REÇUES - AUTHENTIFICATION ===
    Total événements: {len(data)}
    Succès: {success_count}
    Échecs: {failure_count}
    Utilisateurs uniques: {len(users)}
    IPs sources: {len(src_ips)}
    Période: {data[-1].get('timestamp', 'N/A')} à {data[0].get('timestamp', 'N/A')}

    === DÉTAILS AUTHENTIFICATION ==="""
        
        for i, auth in enumerate(data[:12], 1):
            timestamp = auth.get('timestamp', 'N/A')
            agent_id = auth.get('agent_id', 'N/A')
            agent_name = auth.get('agent_name', 'N/A')
            
            srcip = auth.get('srcip', 'N/A')
            rule_desc = auth.get('rule_description', 'Événement authentification')
            level = auth.get('level', 'N/A')
            location = auth.get('location', 'N/A')
            
            # Extraire utilisateur
            full_log = auth.get('full_log', '')
            user_match = re.search(r'user (\w+)|for (\w+)', full_log)
            user = user_match.group(1) or user_match.group(2) if user_match else 'Unknown'
            
            # Déterminer statut
            status = "SUCCESS" if 'success' in rule_desc.lower() else "FAILURE" if 'fail' in rule_desc.lower() else "UNKNOWN"
            
            result += f"""

    [{i}] AUTH {status} L{level} - {timestamp}
    ├── Agent: {agent_id} ({agent_name})
    ├── Utilisateur: {user}
    ├── IP Source: {srcip}
    ├── Localisation: {location}
    └── Règle: {rule_desc}"""
        
        if len(data) > 12:
            result += f"\n\n... et {len(data) - 12} autres événements"
        
        return result

    def format_malware_detection(self, data: List[Dict], question: str) -> str:
        """Format pour détection malware/rootkit"""
        if not data:
            return "Aucune détection de malware/rootkit"
        
        # Analyser détections malware
        detection_types = {}
        agents_affected = set()
        file_paths = set()
        
        for detection in data:
            rule_desc = detection.get('rule_description', '')
            full_log = detection.get('full_log', '')
            
            # Classifier le type de détection
            if 'rootkit' in rule_desc.lower() or 'rootkit' in full_log.lower():
                det_type = 'Rootkit'
            elif 'malware' in rule_desc.lower() or 'virus' in rule_desc.lower():
                det_type = 'Malware'
            elif 'trojan' in rule_desc.lower():
                det_type = 'Trojan'
            elif 'suspicious' in rule_desc.lower():
                det_type = 'Suspicious'
            else:
                det_type = 'Unknown'
            
            detection_types[det_type] = detection_types.get(det_type, 0) + 1
            agents_affected.add(detection.get('agent_id', 'Unknown'))
            
            # Extraire chemin fichier si disponible
            file_match = re.search(r'/[/\w\.-]+', full_log)
            if file_match:
                file_paths.add(file_match.group(0))
        
        result = f"""=== DONNÉES REÇUES - DÉTECTION MALWARE/ROOTKIT ===
    Total détections: {len(data)}
    Types: {dict(detection_types)}
    Agents affectés: {len(agents_affected)}
    Fichiers suspects: {len(file_paths)}
    Période: {data[-1].get('timestamp', 'N/A')} à {data[0].get('timestamp', 'N/A')}

    === DÉTAILS DES DÉTECTIONS ==="""
        
        for i, detection in enumerate(data[:10], 1):
            timestamp = detection.get('timestamp', 'N/A')
            agent_id = detection.get('agent_id', 'N/A')
            agent_name = detection.get('agent_name', 'N/A')
            
            rule_id = detection.get('rule_id', 'N/A')
            rule_desc = detection.get('rule_description', 'Détection malware')
            level = detection.get('level', 'N/A')
            location = detection.get('location', 'N/A')
            
            # Extraire fichier suspect
            full_log = detection.get('full_log', '')
            file_match = re.search(r'/[/\w\.-]+', full_log)
            suspect_file = file_match.group(0) if file_match else 'N/A'
            
            log_preview = full_log[:100] + "..." if len(full_log) > 100 else full_log
            
            result += f"""

    [{i}] DÉTECTION L{level} - {timestamp}
    ├── Agent: {agent_id} ({agent_name})
    ├── Règle: {rule_id} - {rule_desc}
    ├── Localisation: {location}
    ├── Fichier suspect: {suspect_file}
    └── Log: {log_preview}"""
        
        if len(data) > 10:
            result += f"\n\n... et {len(data) - 10} autres détections"
        
        return result

    def format_agent_status(self, data: List[Dict], question: str) -> str:
        """Format pour statut des agents"""
        if not data:
            return "Aucun agent trouvé"
        
        # Analyser statuts agents
        status_counts = {}
        os_types = {}
        versions = {}
        
        for agent in data:
            status = agent.get('status', 'Unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
            
            # OS si disponible
            os_info = agent.get('os', {})
            if isinstance(os_info, dict):
                os_name = os_info.get('name', 'Unknown')
                os_types[os_name] = os_types.get(os_name, 0) + 1
            
            # Version agent
            version = agent.get('version', 'Unknown')
            versions[version] = versions.get(version, 0) + 1
        
        result = f"""=== DONNÉES REÇUES - STATUT AGENTS ===
    Total agents: {len(data)}
    Statuts: {dict(status_counts)}
    Systèmes: {dict(list(os_types.items())[:5])}
    Versions: {dict(list(versions.items())[:3])}

    === DÉTAILS DES AGENTS ==="""
        
        for i, agent in enumerate(data[:15], 1):
            agent_id = agent.get('id', 'N/A')
            name = agent.get('name', 'N/A')
            ip = agent.get('ip', 'N/A')
            status = agent.get('status', 'Unknown')
            last_keep_alive = agent.get('lastKeepAlive', agent.get('last_keepalive', 'N/A'))
            version = agent.get('version', 'N/A')
            
            # Statut avec émoji
            status_icon = "✅" if status == "active" else "❌" if status == "disconnected" else "⚠️"
            
            result += f"""

    [{i}] AGENT {agent_id} {status_icon}
    ├── Nom: {name}
    ├── IP: {ip}
    ├── Statut: {status.upper()}
    ├── Dernière activité: {last_keep_alive}
    └── Version: {version}"""
        
        if len(data) > 15:
            result += f"\n\n... et {len(data) - 15} autres agents"
        
        return result

    def format_disconnected_agents(self, data: List[Dict], question: str) -> str:
        """Format pour agents déconnectés"""
        if not data:
            return "Aucun agent déconnecté"
        
        # Analyser durées de déconnexion
        disconnection_times = {}
        os_affected = {}
        
        for agent in data:
            last_seen = agent.get('lastKeepAlive', agent.get('last_keepalive'))
            if last_seen:
                # Calculer durée approximative (simplified)
                disconnection_times[agent.get('id', 'Unknown')] = last_seen
            
            # OS affecté
            os_info = agent.get('os', {})
            if isinstance(os_info, dict):
                os_name = os_info.get('name', 'Unknown')
                os_affected[os_name] = os_affected.get(os_name, 0) + 1
        
        result = f"""=== DONNÉES REÇUES - AGENTS DÉCONNECTÉS ===
    Total déconnectés: {len(data)}
    Systèmes affectés: {dict(os_affected)}
    Statut: ATTENTION REQUISE

    === DÉTAILS DES AGENTS DÉCONNECTÉS ==="""
        
        for i, agent in enumerate(data[:12], 1):
            agent_id = agent.get('id', 'N/A')
            name = agent.get('name', 'N/A')
            ip = agent.get('ip', 'N/A')
            status = agent.get('status', 'disconnected')
            last_keep_alive = agent.get('lastKeepAlive', agent.get('last_keepalive', 'N/A'))
            
            # OS info
            os_info = agent.get('os', {})
            os_name = os_info.get('name', 'Unknown') if isinstance(os_info, dict) else 'Unknown'
            
            result += f"""

    [{i}] AGENT DÉCONNECTÉ ❌ {agent_id}
    ├── Nom: {name}
    ├── IP: {ip}
    ├── OS: {os_name}
    ├── Statut: {status.upper()}
    └── Dernière activité: {last_keep_alive}"""
        
        if len(data) > 12:
            result += f"\n\n... et {len(data) - 12} autres agents déconnectés"
        
        # Ajouter section recommandations
        result += f"""

    === ACTIONS RECOMMANDÉES ===
    1. Vérifier connectivité réseau des agents déconnectés
    2. Redémarrer service wazuh-agent sur les endpoints
    3. Vérifier configuration firewall/proxy
    4. Contrôler logs système des agents affectés"""
        
        return result

    def format_general_data(self, data: List[Dict], question: str) -> str:
        """Format générique amélioré pour données non spécialisées"""
        if not data:
            return "=== AUCUNE DONNÉE TROUVÉE ==="
        
        # Analyser structure des données pour formater intelligemment
        sample = data[0] if data else {}
        common_fields = ['timestamp', 'agent_id', 'level', 'rule_description', 'rule_id']
        available_fields = [field for field in common_fields if field in sample]
        
        result = f"""=== DONNÉES REÇUES - RECHERCHE GÉNÉRALE ===
    Total éléments: {len(data)}
    Champs disponibles: {available_fields}
    Période: {data[-1].get('timestamp', 'N/A')} à {data[0].get('timestamp', 'N/A')}

    === APERÇU DES DONNÉES ==="""
        
        for i, item in enumerate(data[:10], 1):
            timestamp = item.get('timestamp', 'N/A')
            agent_id = item.get('agent_id', 'N/A')
            level = item.get('level', 'N/A')
            description = item.get('rule_description', item.get('message', str(item)[:100]))
            
            result += f"""

    [{i}] ÉVÉNEMENT L{level} - {timestamp}
    ├── Agent: {agent_id}
    └── Description: {description[:80]}..."""
        
        if len(data) > 10:
            result += f"\n\n... et {len(data) - 10} autres éléments"
        
        return result

enhanced_formatter = EnhancedDataFormatter()

def load_reranker():
    """Charge le re-ranker à la demande avec gestion d'erreur robuste"""
    global reranker, RERANKER_AVAILABLE
    try:
        print("🔄 Chargement du re-ranker CrossEncoder...")
        reranker = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')
        RERANKER_AVAILABLE = True
        print("✅ Re-ranker Cross-Encoder activé")
        return True
    except ImportError as e:
        print(f"⚠️ Dépendances manquantes pour re-ranker: {e}")
        RERANKER_AVAILABLE = False
        return False
    except Exception as e:
        print(f"⚠️ Re-ranker non disponible: {e}")
        RERANKER_AVAILABLE = False
        return False


# =============================================================================
# FONCTIONNALITÉS PRINCIPALES
# =============================================================================

def call_gemini(prompt: str, conversation_id: str = None, 
                             temperature: float = 0.3, max_tokens: int = 2000) -> str:
    max_retries = 3
    base_delay = 2
    
    for attempt in range(max_retries + 1):
        try:
            # Calculer taille du prompt
            prompt_size = len(prompt)
            
            # Gestion intelligente des erreurs 429
            if attempt > 0:
                # Réduire la taille du prompt si nécessaire
                if prompt_size > 4000:
                    prompt = compress_prompt_for_retry(prompt, target_size=3000)
                    print(f"🔧 Prompt compressé: {len(prompt)} caractères")
                
                # Délai exponentiel avec jitter
                delay = base_delay * (2 ** attempt) + (attempt * 0.5)
                print(f"⏳ Attente {delay:.1f}s avant retry {attempt}/{max_retries}...")
                import time
                time.sleep(delay)

            # Contexte conversationnel
            context_prompt = ""
            if conversation_id and conversation_id in conversation_history:
                recent_messages = conversation_history[conversation_id][-1:]
                if recent_messages:
                    last_msg = recent_messages[0]
                    context_prompt = f"CONTEXTE PRÉCÉDENT: {last_msg['question'][:100]}...\n\n"

            full_prompt = context_prompt + prompt

            headers = {"Content-Type": "application/json"}
            params = {"key": GEMINI_API_KEY}
            body = {
                "contents": [{"parts": [{"text": full_prompt}]}],
                "generationConfig": {
                    "temperature": temperature,
                    "maxOutputTokens": max_tokens,
                    "topP": 0.8,
                    "topK": 40
                },
                "safetySettings": [
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"}
                ]
            }

            response = requests.post(GEMINI_URL, headers=headers, params=params, 
                                   json=body, timeout=45)
            
            # Gestion spécifique des codes d'erreur
            if response.status_code == 429:
                if attempt < max_retries:
                    print(f"⚠️ Rate limit atteint, retry {attempt + 1}/{max_retries}")
                    continue
                else:
                    return generate_fallback_response(prompt, "RATE_LIMIT")
            
            elif response.status_code == 503:
                if attempt < max_retries:
                    print(f"⚠️ Service indisponible, retry {attempt + 1}/{max_retries}")
                    continue
                else:
                    return generate_fallback_response(prompt, "SERVICE_UNAVAILABLE")
            
            response.raise_for_status()
            result = response.json()

            candidates = result.get("candidates", [])
            if not candidates:
                if attempt < max_retries:
                    continue
                return generate_fallback_response(prompt, "NO_CANDIDATES")

            parts = candidates[0].get("content", {}).get("parts", [])
            response_text = "".join([p.get("text", "") for p in parts]).strip()

            if response_text:
                return response_text
            elif attempt < max_retries:
                continue
            else:
                return generate_fallback_response(prompt, "EMPTY_RESPONSE")

        except requests.exceptions.Timeout:
            if attempt < max_retries:
                print(f"⚠️ Timeout, retry {attempt + 1}/{max_retries}")
                continue
            return generate_fallback_response(prompt, "TIMEOUT")
            
        except requests.exceptions.ConnectionError:
            if attempt < max_retries:
                print(f"⚠️ Erreur connexion, retry {attempt + 1}/{max_retries}")
                continue
            return generate_fallback_response(prompt, "CONNECTION_ERROR")
            
        except Exception as e:
            if attempt < max_retries:
                print(f"⚠️ Erreur inattendue: {e}, retry {attempt + 1}/{max_retries}")
                continue
            return generate_fallback_response(prompt, f"UNKNOWN_ERROR: {str(e)}")



def compress_prompt_for_retry(prompt: str, target_size: int = 3000) -> str:
    """Compresse intelligemment le prompt en cas d'erreur 429"""
    if len(prompt) <= target_size:
        return prompt
    
    lines = prompt.split('\n')
    essential_parts = []
    current_size = 0
    
    # Priorités pour conserver les informations essentielles
    priority_keywords = ["QUESTION:", "DONNÉES DÉTAILLÉES:", "ALERTES:", "TIMESTAMP:", "AGENT:", "LEVEL:"]
    
    for line in lines:
        line_important = any(keyword in line.upper() for keyword in priority_keywords)
        
        if line_important or current_size < target_size * 0.7:
            if current_size + len(line) < target_size:
                essential_parts.append(line)
                current_size += len(line) + 1
            else:
                # Tronquer la ligne si nécessaire
                remaining = target_size - current_size - 10
                if remaining > 50:
                    essential_parts.append(line[:remaining] + "...")
                break
    
    return '\n'.join(essential_parts)

def generate_fallback_response(original_prompt: str, error_type: str) -> str:
    """Génère une réponse de fallback basée sur l'analyse basique du prompt"""
    fallback_responses = {
        "RATE_LIMIT": """
DONNÉES REÇUES:
- Service temporairement surchargé
- Analyse basique effectuée sur votre requête

ANALYSE RAPIDE:
Votre requête concerne les alertes SOC. En raison de limitations temporaires du service d'analyse, 
voici les actions de base recommandées :
1. Vérifier les logs Wazuh directement
2. Consulter le dashboard pour les alertes critiques
3. Réessayer l'analyse dans quelques minutes

RECOMMANDATION: Réitérez votre question dans 2-3 minutes pour une analyse complète.
""",
        
        "SERVICE_UNAVAILABLE": "Service d'analyse IA temporairement indisponible. Consultez directement les logs Wazuh.",
        "TIMEOUT": "Délai d'analyse dépassé. Requête trop complexe, veuillez reformuler de manière plus spécifique.",
        "NO_CANDIDATES": "Aucune réponse générée. Vérifiez la formulation de votre question.",
        "EMPTY_RESPONSE": "Réponse vide reçue. Problème technique temporaire."
    }
    
    return fallback_responses.get(error_type, f"Erreur technique: {error_type}")

def generate_optimized_prompt(question: str, formatted_data: str, rag_context: str, 
                            system_summary: str) -> str:
    """Génère un prompt optimisé avec instructions claires pour le format de réponse"""
    
    return f"""Tu es un SOC Analyst expert Wazuh. Ton rôle est d'analyser les données de sécurité et fournir des réponses structurées et actionnables.

QUESTION UTILISATEUR: "{question}"

{formatted_data}

CONTEXTE SYSTÈME: {system_summary}
DOCUMENTATION: {rag_context}

INSTRUCTIONS CRITIQUES:
1. Structure ta réponse EXACTEMENT comme suit:

SECTION 1 - SYNTHÈSE DES DONNÉES
• Résume ce qui a été trouvé
• Indique les chiffres clés
• Mentionne la période couverte

SECTION 2 - ANALYSE APPROFONDIE  
• Identifie les patterns suspects
• Corrèle les événements
• Évalue le niveau de risque
• Propose 3 actions prioritaires avec commandes précises

2. Soit précis et technique
3. Base ton analyse UNIQUEMENT sur les données fournies
4. Si données insuffisantes, demande des précisions spécifiques
5. Inclus des commandes Wazuh pratiques

RÉPONSE:"""


def store_conversation(conversation_id: str, question: str, response: str):
    """Stocke l'échange dans l'historique de conversation"""
    if conversation_id not in conversation_history:
        conversation_history[conversation_id] = []

    conversation_history[conversation_id].append({
        'question': question,
        'response': response,
        'timestamp': datetime.now().isoformat()
    })

    # Garder seulement les 10 derniers échanges
    if len(conversation_history[conversation_id]) > 10:
        conversation_history[conversation_id] = conversation_history[conversation_id][-10:]

def extract_key_terms(text: str) -> List[str]:
    """Extrait les termes clés d'un texte pour le contexte"""
    important_terms = {
        'ssh', 'alert', 'agent', 'critical', 'rule', 'network', 'authentication',
        'failed', 'success', 'malware', 'vulnerability', 'intrusion', 'security',
        'level', 'monitoring', 'detection', 'incident', 'firewall'
    }

    words = re.findall(r'\b\w+\b', text.lower())
    key_terms = [word for word in words if word in important_terms]

    return list(set(key_terms))

def retrieve_with_rag(question: str, top_k: int = None, conversation_id: str = None) -> List[Dict]:
    """RAG amélioré avec re-ranker intelligent et gestion d'erreurs"""
    if top_k is None:
        top_k = CONFIG["rag_top_k"]

    try:
        # Enrichissement contextuel de la requête
        enhanced_query = question
        
        # Ajouter contexte conversationnel
        if conversation_id and conversation_id in conversation_history:
            recent_context = conversation_history[conversation_id][-1:]
            if recent_context:
                context_keywords = extract_key_terms(recent_context[0]['question'])
                enhanced_query += f" {' '.join(context_keywords[:3])}"

        # Expansion sémantique spécialisée SOC
        query_expansions = {
            "alerte": "alert detection monitoring incident security critical level high",
            "agent": "endpoint host system monitoring status connection",
            "niveau": "level priority severity critical high medium low",
            "ssh": "authentication connection login security access remote",
            "réseau": "network traffic connection firewall intrusion detection",
            "fichier": "file integrity monitoring syscheck modification change",
            "vulnérabilité": "vulnerability cve security patch exploit weakness"
        }
        
        question_lower = question.lower()
        for keyword, expansion in query_expansions.items():
            if keyword in question_lower:
                enhanced_query += f" {expansion}"

        print(f"🔎 RAG recherche enrichie: {enhanced_query[:100]}...")

        # Recherche vectorielle initiale (plus large si re-ranker disponible)
        search_k = top_k * 4 if RERANKER_AVAILABLE else top_k
        docs = vectorstore.similarity_search(enhanced_query, k=search_k)

        if not docs:
            print("⚠️ Aucun document RAG trouvé")
            return []

        # Re-ranking intelligent si disponible
        if RERANKER_AVAILABLE and reranker is not None and len(docs) > top_k:
            print(f"🎯 Re-ranking {len(docs)} documents...")
            
            try:
                # Préparer les paires (query, document) pour le re-ranker
                pairs = []
                valid_docs = []
                
                for doc in docs:
                    if doc.page_content and len(doc.page_content.strip()) > 20:
                        pairs.append((enhanced_query, doc.page_content[:500]))
                        valid_docs.append(doc)
                
                if pairs:
                    scores = reranker.predict(pairs)
                    
                    # Combiner documents et scores
                    scored_docs = list(zip(valid_docs, scores))
                    scored_docs.sort(key=lambda x: x[1], reverse=True)
                    
                    # Sélectionner les meilleurs
                    docs = [doc for doc, score in scored_docs[:top_k]]
                    print(f"✅ Re-ranking terminé, {len(docs)} docs sélectionnés")
                else:
                    docs = docs[:top_k]
                    
            except Exception as e:
                print(f"⚠️ Erreur re-ranking: {e}, utilisation ordre original")
                docs = docs[:top_k]
        else:
            docs = docs[:top_k]

        return [{"text": d.page_content, "metadata": d.metadata} for d in docs]

    except Exception as e:
        print(f"❌ Erreur recherche RAG: {e}")
        # Fallback avec documentation minimale
        return [{
            "text": "Documentation Wazuh de base disponible pour analyse SOC",
            "metadata": {"type": "fallback", "source": "internal"}
        }]


def truncate_text(text: str, max_chars: int) -> str:
    """Tronque intelligemment le texte"""
    if len(text) <= max_chars:
        return text

    truncated = text[:max_chars]
    last_period = truncated.rfind('.')
    last_space = truncated.rfind(' ')

    if last_period > max_chars * 0.8:
        return truncated[:last_period + 1] + "..."
    elif last_space > max_chars * 0.9:
        return truncated[:last_space] + "..."
    else:
        return truncated + "..."

def get_total_counts() -> Dict[str, int]:
    """Récupère les comptages totaux avec limitation de sécurité"""
    try:
        counts = {}

        alerts_collection = db["alerts"]
        total_alerts = alerts_collection.count_documents({})

        if total_alerts > CONFIG["max_total_count_limit"]:
            total_alerts = alerts_collection.estimated_document_count()
            counts["alerts_estimated"] = True
        else:
            counts["alerts_estimated"] = False

        counts["total_alerts"] = total_alerts

        agents_collection = db["agents"]
        counts["total_agents"] = agents_collection.count_documents({})
        counts["active_agents"] = agents_collection.count_documents({"status": "active"})
        counts["disconnected_agents"] = agents_collection.count_documents({"status": {"$ne": "active"}})

        return counts

    except Exception as e:
        print(f"❌ Erreur comptage total: {e}")
        return {"error": str(e)}

def get_mongodb_summary_compact(days_back: int = None) -> str:
    """Version compacte du résumé pour Gemini"""
    try:
        if days_back is None:
            days_back = CONFIG["default_days_back"]

        summary = []

        total_counts = get_total_counts()
        if "error" not in total_counts:
            if total_counts.get("alerts_estimated"):
                summary.append(f"Total: ~{total_counts['total_alerts']} alertes (estim.)")
            else:
                summary.append(f"Total: {total_counts['total_alerts']} alertes")
            summary.append(f"Agents: {total_counts['active_agents']}/{total_counts['total_agents']} actifs")

        alerts_collection = db["alerts"]
        date_cutoff = datetime.now() - timedelta(days=days_back)

        # Utiliser timestamp au lieu de ingested_at pour la cohérence
        pipeline = [
            {"$match": {"timestamp": {"$gte": date_cutoff.isoformat()}}},
            {"$group": {
                "_id": "$level",
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": -1}},
            {"$limit": 5}
        ]

        level_results = list(alerts_collection.aggregate(pipeline))

        if level_results:
            summary.append(f"Alertes {days_back}j:")
            for result in level_results:
                level = result["_id"]
                count = result["count"]
                severity = "CRIT" if level >= 13 else "ELEV" if level >= 9 else "MOY" if level >= 5 else "INFO"
                summary.append(f"L{level}({severity}):{count}")

        full_summary = " | ".join(summary)
        return truncate_text(full_summary, CONFIG["gemini_summary_max_chars"])

    except Exception as e:
        return f"Erreur données: {e}"

def execute_predefined_query(question: str, custom_limit: int = None) -> Optional[Tuple[List[Dict], str]]:
    """"Version qui récupère toujours tous les détails disponibles"""
    question_lower = question.lower()
    limit = custom_limit or CONFIG["max_query_results"]

    try:
        collection = db["alerts"]
        
        # Projection complète - récupérer TOUS les champs importants
        full_projection = {
            "_id": 0, 
            "timestamp": 1, 
            "agent_id": 1, 
            "agent_name": 1,
            "level": 1,
            "rule_id": 1,
            "rule_description": 1, 
            "decoder_name": 1,
            "location": 1,
            "srcip": 1, 
            "dstip": 1,
            "srcport": 1,
            "dstport": 1,
            "protocol": 1,
            "full_log": 1,  # TOUJOURS inclure le log complet
            "syscheck": 1,
            "vulnerability": 1,
            "data": 1,
            "status": 1,
            "url": 1,
            "id": 1
        }

        # === SSH ÉCHECS ===
        if any(keyword in question_lower for keyword in ["ssh", "connexion"]) and \
                any(keyword in question_lower for keyword in ["échec", "failed", "échoué"]):
            print(f"🔍 Recherche SSH échecs (détails complets)...")
            results = list(collection.find(
                {
                    "$or": [
                        {"rule_description": {"$regex": "Failed.*[Ss][Ss][Hh]|[Ss][Ss][Hh].*Failed", "$options": "i"}},
                        {"rule_id": {"$in": ["5710", "5711", "5712", "5713", "5714", "5716"]}}
                    ]
                },
                full_projection
            ).sort("timestamp", -1).limit(limit))
            return results, "ssh_failed"

        # Voici les parties manquantes à ajouter dans execute_predefined_query après la section SSH :

        # === ALERTES CRITIQUES ===
        elif any(keyword in question_lower for keyword in ["critique", "critical", "urgent"]) and \
                any(keyword in question_lower for keyword in ["alerte", "alert", "événement", "event"]):
            print(f"🔍 Recherche alertes critiques (détails complets)...")
            results = list(collection.find(
                {"level": {"$gte": 13}},
                full_projection
            ).sort("timestamp", -1).limit(limit))
            return results, "critical_alerts"

        # === ALERTES ÉLEVÉES ===
        elif any(keyword in question_lower for keyword in ["élevé", "high", "important"]) and \
                any(keyword in question_lower for keyword in ["alerte", "alert", "niveau", "level"]):
            print(f"🔍 Recherche alertes élevées (détails complets)...")
            results = list(collection.find(
                {"level": {"$gte": 9, "$lt": 13}},
                full_projection
            ).sort("timestamp", -1).limit(limit))
            return results, "high_alerts"

        # === MODIFICATIONS FICHIERS (FIM) ===
        elif any(keyword in question_lower for keyword in ["fichier", "file", "syscheck", "fim"]) and \
                any(keyword in question_lower for keyword in ["modif", "change", "intégrité", "integrity"]):
            print(f"🔍 Recherche modifications fichiers FIM (détails complets)...")
            results = list(collection.find(
                {
                    "$or": [
                        {"decoder_name": "syscheck"},
                        {"rule_id": {"$in": ["550", "551", "552", "553", "554"]}},
                        {"syscheck": {"$exists": True}}
                    ]
                },
                full_projection
            ).sort("timestamp", -1).limit(limit))
            return results, "fim_changes"

        # === VULNÉRABILITÉS ===
        elif any(keyword in question_lower for keyword in ["vulnérabilité", "vulnerability", "cve", "faille"]):
            print(f"🔍 Recherche vulnérabilités (détails complets)...")
            results = list(collection.find(
                {
                    "$or": [
                        {"decoder_name": "vulnerability-detector"},
                        {"vulnerability": {"$exists": True}},
                        {"rule_description": {"$regex": "CVE|vulnerability", "$options": "i"}}
                    ]
                },
                full_projection
            ).sort("timestamp", -1).limit(limit))
            return results, "vulnerabilities"

        # === ACTIVITÉ RÉSEAU ===
        elif any(keyword in question_lower for keyword in ["réseau", "network", "connexion", "connection"]):
            print(f"🔍 Recherche activité réseau (détails complets)...")
            results = list(collection.find(
                {
                    "$or": [
                        {"srcip": {"$exists": True}},
                        {"dstip": {"$exists": True}},
                        {"rule_description": {"$regex": "network|connection|traffic", "$options": "i"}}
                    ]
                },
                full_projection
            ).sort("timestamp", -1).limit(limit))
            return results, "network_activity"

        # === AGENTS ===
        elif any(keyword in question_lower for keyword in ["agent", "endpoint"]):
            if "déconnecté" in question_lower or "disconnect" in question_lower:
                print(f"🔍 Recherche agents déconnectés...")
                agents_collection = db["agents"]
                results = list(agents_collection.find(
                    {"status": {"$ne": "active"}},
                    {"_id": 0, "id": 1, "name": 1, "ip": 1, "status": 1, "lastKeepAlive": 1}
                ).limit(limit))
                return results, "disconnected_agents"
            else:
                print(f"🔍 Recherche statut agents...")
                agents_collection = db["agents"]
                results = list(agents_collection.find(
                    {},
                    {"_id": 0, "id": 1, "name": 1, "ip": 1, "status": 1, "lastKeepAlive": 1}
                ).limit(limit))
                return results, "agent_status"

        # === AUTHENTIFICATION ===
        elif any(keyword in question_lower for keyword in ["auth", "login", "connexion", "authentication"]):
            print(f"🔍 Recherche événements authentification (détails complets)...")
            results = list(collection.find(
                {
                    "$or": [
                        {"decoder_name": {"$in": ["sshd", "pam", "windows"]}},
                        {"rule_description": {"$regex": "authentication|login|logon", "$options": "i"}}
                    ]
                },
                full_projection
            ).sort("timestamp", -1).limit(limit))
            return results, "authentication"

        # === MALWARE/ROOTCHECK ===
        elif any(keyword in question_lower for keyword in ["malware", "virus", "rootkit", "rootcheck"]):
            print(f"🔍 Recherche détection malware/rootkit (détails complets)...")
            results = list(collection.find(
                {
                    "$or": [
                        {"decoder_name": "rootcheck"},
                        {"rule_id": {"$regex": "^51[0-9]"}},  # Règles rootcheck 510-519
                        {"rule_description": {"$regex": "malware|virus|rootkit|trojan", "$options": "i"}}
                    ]
                },
                full_projection
            ).sort("timestamp", -1).limit(limit))
            return results, "malware_detection"

        # === COMPTAGES SPÉCIAUX ===
        elif any(keyword in question_lower for keyword in ["combien", "nombre", "total", "count"]):
            if "agent" in question_lower:
                print(f"🔍 Comptage agents...")
                agents_collection = db["agents"]
                total_agents = agents_collection.count_documents({})
                active_agents = agents_collection.count_documents({"status": "active"})
                disconnected_agents = total_agents - active_agents
                
                return [{
                    "total_agents": total_agents,
                    "active_agents": active_agents,
                    "disconnected_agents": disconnected_agents
                }], "agent_count"
            else:
                print(f"🔍 Comptage total alertes...")
                total_alerts = collection.estimated_document_count()
                return [{"total_alerts": total_alerts, "estimated": True}], "total_count"

        # === RECHERCHE GÉNÉRALE ===
        else:
            print("🔍 Recherche générale (détails complets)...")
            # Recherche par mots-clés dans rule_description et full_log
            search_terms = [term for term in question_lower.split() if len(term) > 2]
            
            if not search_terms:
                # Si pas de termes valides, retourner les dernières alertes
                results = list(collection.find(
                    {},
                    full_projection
                ).sort("timestamp", -1).limit(limit))
                return results, "general_search"
            
            # Échapper les caractères spéciaux pour les regex
            escaped_terms = []
            for term in search_terms:
                # Échapper les caractères spéciaux des regex
                escaped_term = re.escape(term)
                escaped_terms.append(escaped_term)
            
            # Créer une regex valide
            try:
                regex_pattern = "|".join(escaped_terms)
                search_query = {
                    "$or": [
                        {"rule_description": {"$regex": regex_pattern, "$options": "i"}},
                        {"full_log": {"$regex": regex_pattern, "$options": "i"}}
                    ]
                }
                
                results = list(collection.find(
                    search_query,
                    full_projection
                ).sort("timestamp", -1).limit(limit))
                return results, "general_search"
                
            except Exception as regex_error:
                print(f"⚠️ Erreur regex, utilisation de la recherche simple: {regex_error}")
                # Fallback: recherche textuelle simple
                results = list(collection.find(
                    {},
                    full_projection
                ).sort("timestamp", -1).limit(limit))
                return results, "general_search"

        return None, None

    except Exception as e:
        print(f"❌ Erreur requête MongoDB détaillée: {e}")
        return None, None

def add_wazuh_documentation():
    """Documentation SOC complète pour combler les lacunes RAG"""
    print("📚 Ajout documentation SOC complète...")

    comprehensive_docs = [
        # === FIM (File Integrity Monitoring) ===
        {
            "text": "Surveillance intégrité fichiers Wazuh (FIM/syscheck): Module syscheckd surveille modifications /etc/passwd, /etc/shadow, /var/www/html (webshells). Règles 550-554 pour changements fichiers. Configuration: <syscheck><directories>/etc,/var/www</directories></syscheck>. Investigation: analyser checksums, timestamps, permissions modifiées. Webshells communs: shell.php, cmd.asp, backdoor.jsp.",
            "metadata": {"type": "doc", "topic": "fim_syscheck", "category": "security", "priority": "high"}
        },

        # === VULNÉRABILITÉS ===
        {
            "text": "Détection vulnérabilités Wazuh: Module vulnerability-detector scanne packages installés contre base CVE. Configuration wodles vulnerability-detector pour Ubuntu/CentOS/Windows. Alertes CVE critiques: CVSS >= 7.0 nécessitent patch prioritaire. Investigation: wazuh-ctl vulnerability-detector --list-cve, vérifier version package vulnérable, planifier mise à jour système.",
            "metadata": {"type": "doc", "topic": "vulnerability_detection", "category": "security", "priority": "critical"}
        },

        # === ROOTCHECK/MALWARE ===
        {
            "text": "Détection rootkits/malware Wazuh: Module rootcheck cherche processus cachés, ports suspects, fichiers rootkit signatures. Règles 510-514 rootcheck. Détection: ps aux vs /proc differences, netstat ports cachés, checksums système modifiés. Investigation malware: isolated filesystem, memory dump analysis, C2 communication patterns.",
            "metadata": {"type": "doc", "topic": "rootcheck_malware", "category": "security", "priority": "high"}
        },

        # === RÉSEAU ===
        {
            "text": "Surveillance réseau Wazuh: Intégration Suricata/Zeek pour IDS. Détection scans ports (nmap, masscan), connexions C2 suspectes, exfiltration données. Règles 4100+ pour activités réseau. Investigation: analyser flows, géolocalisation IPs, patterns temporels connexions, volumes transferts anormaux.",
            "metadata": {"type": "doc", "topic": "network_monitoring", "category": "security", "priority": "medium"}
        },

        # === CONFORMITÉ ===
        {
            "text": "Conformité Wazuh CIS/HIPAA/PCI-DSS: Module SCA (Security Configuration Assessment) vérifie benchmarks sécurité. Politiques CIS pour Linux/Windows, contrôles HIPAA données médicales, requirements PCI cartes bancaires. Règles 2900+ conformité. Investigation: gap analysis, remediation prioritaire, audit trails.",
            "metadata": {"type": "doc", "topic": "compliance_sca", "category": "compliance", "priority": "medium"}
        },

        # === CORRÉLATION AVANCÉE ===
        {
            "text": "Corrélation événements SOC: Corréler agent déconnecté + CVE critique + tentatives SSH = compromission probable. Timeline reconstruction: login suspect → escalade privilèges → persistence → exfiltration. Investigation playbook: isoler agent, snapshot forensique, analyser artifacts, contenir menace, éradiquer, récupérer.",
            "metadata": {"type": "doc", "topic": "correlation_investigation", "category": "incident_response", "priority": "critical"}
        }
    ]

    try:
        texts = [doc["text"] for doc in comprehensive_docs]
        metadatas = [doc["metadata"] for doc in comprehensive_docs]
        vectorstore.add_texts(texts, metadatas=metadatas)
        print(f"✅ {len(texts)} documents SOC complets ajoutés")
        return True
    except Exception as e:
        print(f"❌ Erreur ajout documentation SOC: {e}")
        return False

def generate_soc_dashboard_summary() -> str:
    """Génère un résumé dashboard SOC multi-sources"""
    try:
        summary = []

        # === 1. ALERTES CRITIQUES ===
        collection = db["alerts"]
        critical_count = collection.count_documents({"level": {"$gte": 13}})
        summary.append(f"🚨 Critiques: {critical_count}")

        # === 2. AGENTS DÉCONNECTÉS ===
        agents_collection = db["agents"]
        disconnected = agents_collection.count_documents({"status": {"$ne": "active"}})
        total_agents = agents_collection.count_documents({})
        summary.append(f"📡 Agents: {total_agents - disconnected}/{total_agents}")

        # === 3. MODIFICATIONS FICHIERS (FIM) ===
        fim_count = collection.count_documents({
            "$or": [
                {"decoder_name": "syscheck"},
                {"rule_id": {"$in": ["550", "551", "552", "553", "554"]}}
            ]
        })
        summary.append(f"📁 FIM: {fim_count}")

        # === 4. VULNÉRABILITÉS ===
        vuln_count = collection.count_documents({
            "$or": [
                {"decoder_name": "vulnerability-detector"},
                {"vulnerability": {"$exists": True}}
            ]
        })
        summary.append(f"🔓 CVE: {vuln_count}")

        # === 5. SSH SUSPECTS ===
        ssh_failed = collection.count_documents({
            "rule_id": {"$in": ["5710", "5711", "5712", "5713", "5714", "5716"]}
        })
        summary.append(f"🔑 SSH: {ssh_failed}")

        return " | ".join(summary)

    except Exception as e:
        return f"❌ Dashboard indisponible: {e}"

def format_soc_analysis_data(limited_data: List[Dict], total_count: int) -> str:
    """Formate les données pour analyse SOC générale"""
    if not limited_data:
        return "Aucun événement SOC détecté"

    formatted_items = []
    for item in limited_data:
        # Extraire les champs les plus pertinents pour SOC
        timestamp = item.get('timestamp', 'N/A')
        agent_id = item.get('agent_id', 'N/A')
        level = item.get('level', 'N/A')
        description = item.get('rule_description', 'N/A')

        # Résumé compact
        summary = f"[{timestamp}] Agent:{agent_id} L{level} - {description[:100]}"
        formatted_items.append(summary)

    result = f"ANALYSE SOC ({len(limited_data)}/{total_count} événements):\n"
    result += "\n".join(formatted_items)

    if total_count > len(limited_data):
        result += f"\n... et {total_count - len(limited_data)} autres événements"

    return result

def format_ssh_failures_data(limited_data: List[Dict], total_count: int) -> str:
    """Formate spécifiquement les échecs SSH"""
    if not limited_data:
        return "Aucun échec SSH détecté"

    formatted_items = []
    ip_counts = {}  # Compter tentatives par IP

    for item in limited_data:
        timestamp = item.get('timestamp', 'N/A')
        agent_id = item.get('agent_id', 'N/A')
        # Gérer les différentes clés possibles pour l'IP source
        srcip = item.get('srcip', item.get('src_ip', 'IP_inconnue'))

        # Compter les IPs
        ip_counts[srcip] = ip_counts.get(srcip, 0) + 1

        summary = f"[{timestamp}] Agent:{agent_id} depuis {srcip}"
        formatted_items.append(summary)

    result = f"ÉCHECS SSH ({len(limited_data)}/{total_count} tentatives):\n"
    result += "\n".join(formatted_items[:5])  # Limiter à 5 pour lisibilité

    # Ajouter top IPs suspectes
    if ip_counts:
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        result += f"\nTOP IPs suspectes: {', '.join([f'{ip}({count})' for ip, count in top_ips])}"

    return result

def format_critical_alerts_data(limited_data: List[Dict], total_count: int) -> str:
    """Formate spécifiquement les alertes critiques"""
    if not limited_data:
        return "Aucune alerte critique détectée"

    formatted_items = []
    level_counts = {}

    for item in limited_data:
        timestamp = item.get('timestamp', 'N/A')
        agent_id = item.get('agent_id', 'N/A')
        level = item.get('level', 'N/A')
        description = item.get('rule_description', 'N/A')

        level_counts[level] = level_counts.get(level, 0) + 1

        summary = f"[{timestamp}] Agent:{agent_id} NIVEAU-{level} - {description[:80]}"
        formatted_items.append(summary)

    result = f"ALERTES CRITIQUES ({len(limited_data)}/{total_count}):\n"
    result += "\n".join(formatted_items)

    # Ajouter répartition par niveau
    if level_counts:
        levels_summary = ", ".join([f"L{level}:{count}" for level, count in sorted(level_counts.items(), reverse=True)])
        result += f"\nRépartition: {levels_summary}"

    return result

def format_fim_data(limited_data: List[Dict], total_count: int) -> str:
    """Formate les données FIM (File Integrity Monitoring)"""
    if not limited_data:
        return "Aucune modification de fichier détectée"

    formatted_items = []
    file_paths = set()

    for item in limited_data:
        timestamp = item.get('timestamp', 'N/A')
        agent_id = item.get('agent_id', 'N/A')

        # Extraire chemin fichier si disponible
        syscheck_data = item.get('syscheck', {})
        file_path = syscheck_data.get('path', 'fichier_inconnu')
        file_paths.add(file_path)

        summary = f"[{timestamp}] Agent:{agent_id} - {file_path}"
        formatted_items.append(summary)

    result = f"MODIFICATIONS FICHIERS FIM ({len(limited_data)}/{total_count}):\n"
    result += "\n".join(formatted_items)

    if len(file_paths) > 1:
        result += f"\nFichiers concernés: {len(file_paths)} différents"

    return result

def format_vulnerability_data(limited_data: List[Dict], total_count: int) -> str:
    """Formate les données de vulnérabilités"""
    if not limited_data:
        return "Aucune vulnérabilité détectée"

    formatted_items = []
    severity_counts = {}

    for item in limited_data:
        timestamp = item.get('timestamp', 'N/A')
        agent_id = item.get('agent_id', 'N/A')

        # Extraire info vulnérabilité
        vuln_data = item.get('vulnerability', {})
        cve = vuln_data.get('cve', 'CVE_inconnu')
        severity = vuln_data.get('severity', 'Unknown')

        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        summary = f"[{timestamp}] Agent:{agent_id} - {cve} ({severity})"
        formatted_items.append(summary)

    result = f"VULNÉRABILITÉS ({len(limited_data)}/{total_count}):\n"
    result += "\n".join(formatted_items)

    # Ajouter répartition par sévérité
    if severity_counts:
        sev_summary = ", ".join([f"{sev}:{count}" for sev, count in severity_counts.items()])
        result += f"\nSévérités: {sev_summary}"

    return result

def format_generic_data(limited_data: List[Dict], total_count: int) -> str:
    """Formate les données génériques"""
    if not limited_data:
        return "Aucune donnée trouvée"

    formatted_items = []
    for item in limited_data:
        # Tentative d'extraction des champs les plus communs
        timestamp = item.get('timestamp', 'N/A')
        agent_id = item.get('agent_id', 'N/A')

        # Chercher un champ descriptif
        description = (item.get('rule_description') or
                       item.get('message') or
                       item.get('event') or
                       str(item)[:100])

        summary = f"[{timestamp}] Agent:{agent_id} - {description}"
        formatted_items.append(summary)

    result = f"DONNÉES ({len(limited_data)}/{total_count}):\n"
    result += "\n".join(formatted_items)

    return result

def prepare_mongodb_data_for_gemini(mongodb_data: Optional[List], query_type: str, question: str) -> str:
    if not mongodb_data:
        return "=== AUCUNE DONNÉE SPÉCIFIQUE TROUVÉE ==="
    
    # Gestion spéciale pour les comptages simples
    if query_type in ["total_count", "agent_count"]:
        data = mongodb_data[0]
        if query_type == "total_count":
            if data.get("estimated"):
                return f"TOTAL ALERTES: ~{data['total_alerts']} (estimation)"
            else:
                return f"TOTAL ALERTES: {data['total_alerts']} (exact)"
        elif query_type == "agent_count":
            return f"AGENTS: {data['active_agents']}/{data['total_agents']} actifs, {data['disconnected_agents']} déconnectés"
    
    # Utiliser le gestionnaire adaptatif pour tous les autres cas
    return data_manager.prepare_data(mongodb_data, query_type, question)


def prepare_rag_data_for_gemini(rag_results: List[Dict]) -> str:
    """Prépare les données RAG pour Gemini avec limitation intelligente"""
    if not rag_results:
        return "Documentation non disponible"

    max_docs = CONFIG["gemini_max_rag_docs"]
    limited_docs = rag_results[:max_docs]

    doc_texts = []
    for doc in limited_docs:
        text = doc.get("text", "")
        truncated = truncate_text(text, 400)
        doc_texts.append(truncated)

    return " | ".join(doc_texts)

def generate_chatbot_response(question: str, formatted_data: str,
                                     system_summary: str, rag_context: str,
                                     conversation_id: str = None) -> str:
    """Génération adaptative selon la quantité de données"""
    
    soc_dashboard = generate_soc_dashboard_summary()

    # Estimer la taille totale du prompt
    base_prompt_size = len(question) + len(system_summary) + len(rag_context) + len(soc_dashboard) + 1000  # +1000 pour les instructions
    data_size = len(formatted_data)
    total_size = base_prompt_size + data_size
    
    # Ajuster les instructions selon la taille
    if total_size > 6000:  # Données volumineuses
        instruction_level = "ANALYSE_CONDENSEE"
        max_tokens = 1500
    elif data_size > 2000:  # Données moyennes
        instruction_level = "ANALYSE_STANDARD"
        max_tokens = 2000
    else:  # Données légères
        instruction_level = "ANALYSE_COMPLETE"
        max_tokens = 2500

    prompt = f"""Tu es un SOC Analyst expert Wazuh. Mode: {instruction_level}

QUESTION: "{question}"

DASHBOARD SOC: {soc_dashboard}

DONNÉES DÉTAILLÉES:
{formatted_data}

CONTEXTE SYSTÈME: {system_summary}

DOCUMENTATION: {rag_context}

INSTRUCTIONS ADAPTATIVES ({instruction_level}):
{get_analysis_instructions(instruction_level)}

Réponse SOC analyst:"""

    return call_gemini(prompt, conversation_id, temperature=0.1, max_tokens=max_tokens)

def get_analysis_instructions(level: str) -> str:
    """Instructions adaptatives selon le volume de données"""
    
    instructions = {
        "ANALYSE_CONDENSEE": """
- Synthèse technique précise et concise
- Actions prioritaires uniquement (top 3)
- Corrélations essentielles
- Format compact mais complet""",
        
        "ANALYSE_STANDARD": """
- Analyse équilibrée détail/concision  
- Actions immédiates + recommandations
- Contexte de menace si pertinent
- Investigation si nécessaire""",
        
        "ANALYSE_COMPLETE": """
- Analyse approfondie de tous les éléments
- Actions détaillées avec commandes
- Recommandations préventives étendues
- Investigation complète si incident
- Corrélation multi-sources avancée"""
    }
    
    return instructions.get(level, instructions["ANALYSE_STANDARD"])



def process_question(question: str, custom_limits: Dict = None, 
                            conversation_id: str = None) -> str:
    """Pipeline principal optimisé avec gestion d'erreurs robuste"""
    print(f"\n{'=' * 60}")
    print(f"Question: {question}")
    print(f"Mode: OPTIMISÉ AVEC RE-RANKER")

    try:
        # 1. Exécution requête MongoDB avec gestion d'erreur
        print("🔧 Recherche MongoDB détaillée...")
        try:
            mongodb_results, query_type = execute_predefined_query(question)
        except Exception as e:
            print(f"❌ Erreur MongoDB: {e}")
            mongodb_results, query_type = [], "error"

        print("🔧 Recherche documentation RAG...")
        try:
            rag_results = retrieve_with_rag(question, 
                                                   CONFIG["gemini_max_rag_docs"], 
                                                   conversation_id)
            rag_context = prepare_rag_data_for_gemini(rag_results)
        except Exception as e:
            print(f"❌ Erreur RAG: {e}")
            rag_context = "Documentation temporairement indisponible"

        # 3. Résumé système
        print("🔧 Génération résumé système...")
        try:
            system_summary = get_mongodb_summary_compact()
        except Exception as e:
            print(f"❌ Erreur résumé système: {e}")
            system_summary = "Résumé système temporairement indisponible"

        # 4. Formatage spécialisé des données
        print("🔧 Formatage des données...")
        formatted_data = enhanced_formatter.format_data(mongodb_results or [], 
                                             query_type or "general_search", 
                                             question)

        # 5. Génération prompt optimisé
        optimized_prompt = generate_optimized_prompt(question, formatted_data, 
                                                   rag_context, system_summary)

        # 6. Appel Gemini avec fallback
        print("🔧 Génération réponse avec IA...")
        answer = call_gemini(optimized_prompt, conversation_id, 
                                         temperature=0.1, max_tokens=2500)

        # 7. Stockage conversation
        if conversation_id:
            store_conversation(conversation_id, question, answer)

        return answer

    except Exception as e:
        print(f"❌ Erreur pipeline: {e}")
        import traceback
        traceback.print_exc()
        
        return f"""ERREUR SYSTÈME:
Une erreur technique s'est produite lors du traitement de votre question.
Erreur: {str(e)}

ACTIONS RECOMMANDÉES:
1. Vérifiez la connectivité aux services (MongoDB, Gemini API)
2. Reformulez votre question de manière plus simple
3. Contactez l'administrateur système si le problème persiste

Vous pouvez aussi essayer une question plus spécifique comme:
- "Montrer les 10 dernières alertes critiques"
- "Statut des agents Wazuh"
- "Échecs SSH des dernières 24h"
"""

def set_processing_limits(**kwargs):
    """Permet d'ajuster les limites de traitement"""
    for key, value in kwargs.items():
        if key in CONFIG:
            CONFIG[key] = value
            print(f"⚙️ Limite mise à jour: {key} = {value}")
        else:
            print(f"⚠️ Limite inconnue: {key}")

def get_current_limits():
    """Retourne les limites actuelles"""
    return CONFIG.copy()

def validate_system():
    """Validation du système hybride"""
    issues = []

    # Test MongoDB
    try:
        client.admin.command('ping')
        print("✅ MongoDB connecté")

        collections = db.list_collection_names()
        if not collections:
            issues.append("⚠️ MongoDB: Aucune collection trouvée")
        else:
            print(f"📋 Collections disponibles: {collections}")

            alerts_count = db["alerts"].count_documents({})
            agents_count = db["agents"].count_documents({})
            print(f"   - Alertes: {alerts_count}")
            print(f"   - Agents: {agents_count}")

    except Exception as e:
        issues.append(f"❌ MongoDB: {e}")

    # Test Gemini
    try:
        test_response = call_gemini("Réponds juste 'TEST OK'", max_tokens=10)
        if "Erreur" not in test_response:
            print("✅ Gemini API opérationnel")
        else:
            issues.append(f"❌ Gemini: {test_response}")
    except Exception as e:
        issues.append(f"❌ Gemini: {e}")

    # Test base vectorielle
    try:
        # Méthode plus robuste pour compter les documents
        collection_info = vectorstore.get()
        collection_count = len(collection_info.get("ids", []))
        print(f"✅ Base vectorielle accessible ({collection_count} documents)")

        if collection_count < 10:
            print("⚠️ Base vectorielle contient peu de documents - ajout de documentation...")
            add_wazuh_documentation()

    except Exception as e:
        issues.append(f"❌ Vectorstore: {e}")

    if issues:
        print("\n".join(issues))
        return False

    print("🎉 Système hybride opérationnel")
    return True


