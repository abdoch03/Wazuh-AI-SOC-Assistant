import requests
import json
import base64
import time
import hashlib
from datetime import datetime, timedelta, UTC
from pymongo import MongoClient
import sys
import os
from dotenv import load_dotenv

from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

load_dotenv()

MANAGER_USER = os.getenv("WAZUH_MANAGER_USER", "wazuh")
MANAGER_PASSWORD = os.getenv("WAZUH_MANAGER_PASSWORD")
MANAGER_API_URL = os.getenv("WAZUH_MANAGER_API_URL", "https://192.168.1.100:55000")

INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD")
INDEXER_API_URL = os.getenv("WAZUH_INDEXER_API_URL", "https://192.168.1.100:9200")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "wazuh_siem")

HUGGINGFACE_MODEL = os.getenv("HUGGINGFACE_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
VECTOR_DB_DIR = os.getenv("VECTOR_DB_DIR", "./chroma_db")

embeddings = HuggingFaceEmbeddings(model_name=HUGGINGFACE_MODEL)


try:
    vectorstore = Chroma(
        collection_name="wazuh_data",
        embedding_function=embeddings,
        persist_directory=VECTOR_DB_DIR
    )
    print(f"✅ ChromaDB initialisé dans: {VECTOR_DB_DIR}")
except Exception as e:
    print(f"❌ Erreur initialisation ChromaDB: {e}")
    sys.exit(1)

def validate_env_config():
    required_vars = {
        'WAZUH_MANAGER_API_URL': MANAGER_API_URL,
        'WAZUH_MANAGER_USER': MANAGER_USER,
        'WAZUH_MANAGER_PASSWORD': MANAGER_PASSWORD,
        'WAZUH_INDEXER_API_URL': INDEXER_API_URL,
        'WAZUH_INDEXER_USER': INDEXER_USER,
        'WAZUH_INDEXER_PASSWORD': INDEXER_PASSWORD,
        'MONGO_URI': MONGO_URI,
        'MONGO_DB_NAME': MONGO_DB_NAME
    }
    
    missing_vars = [var for var, value in required_vars.items() if not value]
    
    if missing_vars:
        print("❌ Variables d'environnement manquantes :")
        for var in missing_vars:
            print(f"   - {var}")
        sys.exit(1)
    
    print("✅ Configuration environnement validée")


class DataDeduplicator:
    """Gestionnaire de déduplication pour éviter les redondances"""

    def __init__(self, db):
        self.db = db
        self._initialize_dedup_collections()

    def _initialize_dedup_collections(self):
        """Crée les collections de suivi des hash si nécessaire"""
        collections = [
            "content_hashes",  # Hash des contenus vectorisés
            "data_fingerprints"  # Empreintes des données MongoDB
        ]
        for coll_name in collections:
            if coll_name not in self.db.list_collection_names():
                self.db.create_collection(coll_name)
                print(f"📁 Collection de déduplication '{coll_name}' créée")

    def generate_content_hash(self, text_content):
        """Génère un hash unique basé sur le contenu textuel"""
        # Normaliser le texte (supprimer espaces multiples, lowercase)
        normalized = ' '.join(text_content.lower().strip().split())
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

    def generate_data_fingerprint(self, data_dict, key_fields):
        """Génère une empreinte unique basée sur des champs clés"""
        fingerprint_data = {}
        for field in key_fields:
            if field in data_dict:
                fingerprint_data[field] = str(data_dict[field])

        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.md5(fingerprint_str.encode('utf-8')).hexdigest()

    def is_content_duplicate(self, text_content, data_type):
        """Vérifie si un contenu textuel est déjà vectorisé"""
        content_hash = self.generate_content_hash(text_content)

        existing = self.db["content_hashes"].find_one({
            "content_hash": content_hash,
            "type": data_type
        })

        if existing:
            # Mettre à jour le timestamp de dernière vue
            self.db["content_hashes"].update_one(
                {"_id": existing["_id"]},
                {"$set": {"last_seen": datetime.now(UTC)}}
            )
            return True

        return False

    def mark_content_as_processed(self, text_content, data_type, metadata=None):
        """Marque un contenu comme déjà vectorisé"""
        content_hash = self.generate_content_hash(text_content)

        doc = {
            "content_hash": content_hash,
            "type": data_type,
            "first_seen": datetime.now(UTC),
            "last_seen": datetime.now(UTC),
            "metadata": metadata or {}
        }

        self.db["content_hashes"].update_one(
            {"content_hash": content_hash, "type": data_type},
            {"$set": doc},
            upsert=True
        )

    def is_data_duplicate(self, data_dict, data_type, key_fields):
        """Vérifie si des données sont déjà stockées en base"""
        fingerprint = self.generate_data_fingerprint(data_dict, key_fields)

        existing = self.db["data_fingerprints"].find_one({
            "fingerprint": fingerprint,
            "type": data_type
        })

        if existing:
            self.db["data_fingerprints"].update_one(
                {"_id": existing["_id"]},
                {"$set": {"last_seen": datetime.now(UTC)}}
            )
            return True

        return False

    def mark_data_as_processed(self, data_dict, data_type, key_fields):
        """Marque des données comme déjà traitées"""
        fingerprint = self.generate_data_fingerprint(data_dict, key_fields)

        doc = {
            "fingerprint": fingerprint,
            "type": data_type,
            "key_fields": key_fields,
            "first_seen": datetime.now(UTC),
            "last_seen": datetime.now(UTC)
        }

        self.db["data_fingerprints"].update_one(
            {"fingerprint": fingerprint, "type": data_type},
            {"$set": doc},
            upsert=True
        )

    def cleanup_old_hashes(self, days=30):
        """Nettoie les hash anciens pour éviter l'accumulation"""
        cutoff_date = datetime.now(UTC) - timedelta(days=days)

        result1 = self.db["content_hashes"].delete_many({
            "last_seen": {"$lt": cutoff_date}
        })

        result2 = self.db["data_fingerprints"].delete_many({
            "last_seen": {"$lt": cutoff_date}
        })

        print(f"🧹 Nettoyage: {result1.deleted_count} hash contenus + {result2.deleted_count} empreintes supprimés")


class WazuhDBManager:
    def __init__(self, uri, db_name):
        try:
            self.client = MongoClient(uri, serverSelectionTimeoutMS=5000)
            self.db = self.client.get_database(db_name)
            self.client.admin.command('ping')
            print(f"✅ Connexion à MongoDB réussie. Base de données : '{db_name}'")

            # Initialiser le déduplicateur
            self.deduplicator = DataDeduplicator(self.db)

        except Exception as e:
            print(f"❌ Erreur de connexion à MongoDB : {e}")
            sys.exit(1)

    def insert_agents(self, agents_data):
        if not agents_data: return

        agents_collection = self.db["agents"]
        new_count, updated_count = 0, 0

        for agent in agents_data:
            # Vérifier les doublons basés sur agent_id + statut + version
            if not self.deduplicator.is_data_duplicate(
                    agent, "agent", ["agent_id", "status", "version", "last_checkin"]
            ):
                result = agents_collection.update_one(
                    {"agent_id": agent["agent_id"]},
                    {"$set": {**agent, "last_updated": datetime.now(UTC)}},
                    upsert=True
                )

                if result.upserted_id:
                    new_count += 1
                elif result.modified_count > 0:
                    updated_count += 1

                self.deduplicator.mark_data_as_processed(
                    agent, "agent", ["agent_id", "status", "version", "last_checkin"]
                )

        if new_count > 0 or updated_count > 0:
            print(f"➡️  Agents: {new_count} nouveaux, {updated_count} mis à jour")

    def insert_alerts(self, alerts_data):
        if not alerts_data: return

        alerts_collection = self.db["alerts"]
        new_or_updated_alerts = []

        for alert in alerts_data:
            # Clés uniques pour déduplication des alertes
            key_fields = ["alert_id", "timestamp", "agent_id", "rule_id"]

            if not self.deduplicator.is_data_duplicate(alert, "alert", key_fields):
                result = alerts_collection.update_one(
                    {"alert_id": alert["alert_id"]},
                    {"$set": {**alert, "last_updated": datetime.now(UTC)}},
                    upsert=True
                )

                if result.upserted_id or result.modified_count > 0:
                    new_or_updated_alerts.append(alert)
                    self.deduplicator.mark_data_as_processed(alert, "alert", key_fields)

        print(f"➡️  Alertes: {len(alerts_data)} traitées. {len(new_or_updated_alerts)} nouvelles/mises à jour.")

        # === VECTORISATION ANTI-REDONDANCE ===
        texts_to_vectorize, metadatas_to_vectorize = [], []

        for alert in new_or_updated_alerts:
            # Gestion des valeurs None
            rule_desc = alert.get('rule_description', '') or ''
            agent_id = alert.get('agent_id', '') or ''
            level = alert.get('level', 0) or 0
            log_data = alert.get('log', {}) or {}
            timestamp = alert.get('timestamp', '') or ''

            text_parts = []

            if level >= 13:
                text_parts.append("ALERTE CRITIQUE")
            elif level >= 9:
                text_parts.append("ALERTE ÉLEVÉE")
            elif level >= 5:
                text_parts.append("ALERTE MOYENNE")
            else:
                text_parts.append("INFORMATION")

            text_parts.append(f"Niveau {level}")
            text_parts.append(f"Règle: {rule_desc}")

            # Vérification que rule_desc n'est pas None avant .lower()
            if rule_desc and any(keyword in rule_desc.lower() for keyword in ['ssh', 'authentication', 'login']):
                text_parts.append("Type: Authentification SSH")
                if rule_desc and any(keyword in rule_desc.lower() for keyword in ['failed', 'failure', 'denied']):
                    text_parts.append("Résultat: Tentative de connexion échouée - Risque d'attaque par force brute")
                elif rule_desc and any(
                        keyword in rule_desc.lower() for keyword in ['success', 'accepted', 'successful']):
                    text_parts.append("Résultat: Connexion SSH réussie")

            if log_data and log_data.get('source_ip'):
                text_parts.append(f"Adresse IP source: {log_data['source_ip']}")
            if log_data and log_data.get('username'):
                text_parts.append(f"Nom d'utilisateur: {log_data['username']}")
            if log_data and log_data.get('destination_ip'):
                text_parts.append(f"Destination: {log_data['destination_ip']}")

            text_parts.append(f"Agent concerné: {agent_id}")

            if timestamp:
                text_parts.append(f"Horodatage: {timestamp}")

            full_log = alert.get('full_log', '')
            if full_log and full_log.strip() and full_log != "None":
                text_parts.append(f"Détails: {full_log}")

            enriched_text = " | ".join(text_parts)

            # VÉRIFIER LES DOUBLONS DE CONTENU AVANT VECTORISATION
            if not self.deduplicator.is_content_duplicate(enriched_text, "alert"):
                texts_to_vectorize.append(enriched_text)

                metadata = {
                    "type": "alert",
                    "alert_id": str(alert.get("alert_id", "")),
                    "timestamp": str(timestamp),
                    "agent_id": str(agent_id),
                    "level": int(level),
                    "severity": "critical" if level >= 13 else "high" if level >= 9 else "medium" if level >= 5 else "info",
                    "rule_description": str(rule_desc)[:500] if rule_desc else "",
                    "category": "ssh" if rule_desc and "ssh" in rule_desc.lower() else "security"
                }
                metadatas_to_vectorize.append(metadata)

                # Marquer comme traité
                self.deduplicator.mark_content_as_processed(
                    enriched_text, "alert",
                    {"alert_id": alert.get("alert_id"), "agent_id": agent_id}
                )

        # Vectoriser uniquement les nouveaux contenus
        if texts_to_vectorize:
            try:
                vectorstore.add_texts(texts_to_vectorize, metadatas=metadatas_to_vectorize)
                print(
                    f"📥 {len(texts_to_vectorize)} alertes UNIQUES vectorisées (sur {len(new_or_updated_alerts)} candidates)")
            except Exception as e:
                print(f"❌ Erreur vectorisation alertes: {e}")
        else:
            print("📥 Aucune nouvelle alerte unique à vectoriser")

    def insert_rules(self, rules_data):
        """Version optimisée anti-redondance pour règles"""
        if not rules_data: return

        rules_collection = self.db["rules"]
        new_or_updated_rules = []

        for rule in rules_data:
            key_fields = ["rule_id", "description", "level"]

            if not self.deduplicator.is_data_duplicate(rule, "rule", key_fields):
                result = rules_collection.update_one(
                    {"rule_id": rule["rule_id"]},
                    {"$set": {**rule, "last_updated": datetime.now(UTC)}},
                    upsert=True
                )

                if result.upserted_id or result.modified_count > 0:
                    new_or_updated_rules.append(rule)
                    self.deduplicator.mark_data_as_processed(rule, "rule", key_fields)

        print(f"➡️  Règles: {len(rules_data)} traitées. {len(new_or_updated_rules)} nouvelles/mises à jour.")

        # Vectorisation anti-redondance des règles
        texts_to_vectorize, metadatas_to_vectorize = [], []

        for rule in new_or_updated_rules:
            rule_id = rule.get("rule_id")
            description = rule.get("description", "")
            level = rule.get("level", 0)
            groups = rule.get("groups", [])

            text_parts = []
            text_parts.append(f"Règle Wazuh ID {rule_id}")
            text_parts.append(f"Description: {description}")
            text_parts.append(f"Niveau de sévérité: {level}")

            if groups:
                text_parts.append(f"Groupes: {', '.join(groups)}")

            if any(group in ['ssh', 'authentication'] for group in groups):
                text_parts.append("Catégorie: Authentification SSH et sécurité d'accès")
            elif any(group in ['web', 'apache', 'nginx'] for group in groups):
                text_parts.append("Catégorie: Sécurité web et serveurs HTTP")
            elif any(group in ['firewall', 'network'] for group in groups):
                text_parts.append("Catégorie: Sécurité réseau et firewall")
            elif any(group in ['malware', 'virus'] for group in groups):
                text_parts.append("Catégorie: Détection de malware et antivirus")

            enriched_text = " | ".join(text_parts)

            # Vérification anti-doublons
            if not self.deduplicator.is_content_duplicate(enriched_text, "rule"):
                texts_to_vectorize.append(enriched_text)

                metadatas_to_vectorize.append({
                    "type": "rule",
                    "rule_id": str(rule_id),
                    "level": int(level),
                    "groups": ", ".join(groups) if groups else "",
                    "category": "security_rule"
                })

                self.deduplicator.mark_content_as_processed(
                    enriched_text, "rule", {"rule_id": rule_id}
                )

        if texts_to_vectorize:
            try:
                vectorstore.add_texts(texts_to_vectorize, metadatas=metadatas_to_vectorize)
                print(f"📥 {len(texts_to_vectorize)} règles UNIQUES vectorisées")
            except Exception as e:
                print(f"❌ Erreur vectorisation règles: {e}")
        else:
            print("📥 Aucune nouvelle règle unique à vectoriser")

    def insert_syscollector_data(self, syscollector_data):
        """Version optimisée pour syscollector"""
        if not syscollector_data: return

        syscollector_collection = self.db["syscollector"]
        new_count, updated_count = 0, 0

        for agent_data in syscollector_data:
            # Clés pour détecter les changements significatifs
            key_fields = ["agent_id", "os_info", "processes", "ports"]

            if not self.deduplicator.is_data_duplicate(agent_data, "syscollector", key_fields):
                result = syscollector_collection.update_one(
                    {"agent_id": agent_data["agent_id"]},
                    {"$set": {**agent_data, "last_updated": datetime.now(UTC)}},
                    upsert=True
                )

                if result.upserted_id:
                    new_count += 1
                elif result.modified_count > 0:
                    updated_count += 1

                self.deduplicator.mark_data_as_processed(agent_data, "syscollector", key_fields)

        if new_count > 0 or updated_count > 0:
            print(f"➡️  Syscollector: {new_count} nouveaux, {updated_count} mis à jour")

    def insert_vulnerabilities(self, vulns_data):
        """Version optimisée pour vulnérabilités"""
        if not vulns_data: return

        vulns_collection = self.db["vulnerabilities"]
        new_or_updated_vulns = []

        for vuln in vulns_data:
            key_fields = ["agent_id", "cve", "package.name", "severity"]

            if not self.deduplicator.is_data_duplicate(vuln, "vulnerability", key_fields):
                cve_id = vuln.get("cve", "N/A")
                package_name = vuln.get("package", {}).get("name", "unknown")

                result = vulns_collection.update_one(
                    {
                        "agent_id": vuln["agent_id"],
                        "cve": cve_id,
                        "package.name": package_name
                    },
                    {"$set": {**vuln, "last_updated": datetime.now(UTC)}},
                    upsert=True
                )

                if result.upserted_id or result.modified_count > 0:
                    new_or_updated_vulns.append(vuln)
                    self.deduplicator.mark_data_as_processed(vuln, "vulnerability", key_fields)

        print(f"➡️  Vulnérabilités: {len(vulns_data)} traitées. {len(new_or_updated_vulns)} nouvelles/mises à jour.")

        # Vectorisation anti-redondance
        texts_to_vectorize, metadatas_to_vectorize = [], []

        for vuln in new_or_updated_vulns:
            cve = vuln.get('cve', 'N/A')
            title = vuln.get('title', '')
            severity = vuln.get('severity', 'Unknown')
            package = vuln.get('package', {})
            agent_id = vuln.get('agent_id', '')

            text_parts = []
            text_parts.append(f"Vulnérabilité {cve}")
            if title:
                text_parts.append(f"Titre: {title}")
            text_parts.append(f"Sévérité: {severity}")
            if package.get('name'):
                text_parts.append(f"Package affecté: {package['name']}")
                if package.get('version'):
                    text_parts.append(f"Version: {package['version']}")
            text_parts.append(f"Agent: {agent_id}")

            enriched_text = " | ".join(text_parts)

            if not self.deduplicator.is_content_duplicate(enriched_text, "vulnerability"):
                texts_to_vectorize.append(enriched_text)

                metadatas_to_vectorize.append({
                    "type": "vulnerability",
                    "agent_id": agent_id,
                    "cve": cve,
                    "severity": severity,
                    "category": "security_vulnerability"
                })

                self.deduplicator.mark_content_as_processed(
                    enriched_text, "vulnerability", {"cve": cve, "agent_id": agent_id}
                )

        if texts_to_vectorize:
            try:
                vectorstore.add_texts(texts_to_vectorize, metadatas=metadatas_to_vectorize)
                print(f"📥 {len(texts_to_vectorize)} vulnérabilités UNIQUES vectorisées")
            except Exception as e:
                print(f"❌ Erreur vectorisation vulnérabilités: {e}")

    def insert_sca_results(self, sca_data):
        """Version optimisée pour SCA"""
        if not sca_data: return

        sca_collection = self.db["sca_results"]
        new_or_updated_sca = []

        for result in sca_data:
            key_fields = ["agent_id", "policy_id", "score", "pass", "fail"]

            if not self.deduplicator.is_data_duplicate(result, "sca", key_fields):
                res = sca_collection.update_one(
                    {"agent_id": result["agent_id"], "policy_id": result.get("policy_id")},
                    {"$set": {**result, "last_updated": datetime.now(UTC)}},
                    upsert=True
                )

                if res.upserted_id or res.modified_count > 0:
                    new_or_updated_sca.append(result)
                    self.deduplicator.mark_data_as_processed(result, "sca", key_fields)

        print(f"➡️  SCA: {len(sca_data)} traités. {len(new_or_updated_sca)} nouveaux/mis à jour.")

        # Vectorisation anti-redondance SCA
        texts_to_vectorize, metadatas_to_vectorize = [], []

        for sca in new_or_updated_sca:
            name = sca.get('name', '')
            description = sca.get('description', '')
            score = sca.get('score', 0)
            pass_count = sca.get('pass', 0)
            fail_count = sca.get('fail', 0)
            agent_id = sca.get('agent_id', '')
            policy_id = sca.get('policy_id', '')

            text_parts = []
            text_parts.append(f"Évaluation de conformité SCA")
            if name:
                text_parts.append(f"Politique: {name}")
            if description:
                text_parts.append(f"Description: {description}")
            text_parts.append(f"Score de conformité: {score}%")
            text_parts.append(f"Tests réussis: {pass_count}")
            text_parts.append(f"Tests échoués: {fail_count}")
            text_parts.append(f"Agent: {agent_id}")

            if score >= 90:
                text_parts.append("Niveau: Conformité excellente")
            elif score >= 75:
                text_parts.append("Niveau: Conformité bonne")
            elif score >= 50:
                text_parts.append("Niveau: Conformité moyenne - Action requise")
            else:
                text_parts.append("Niveau: Conformité faible - Action urgente")

            enriched_text = " | ".join(text_parts)

            if not self.deduplicator.is_content_duplicate(enriched_text, "sca"):
                texts_to_vectorize.append(enriched_text)

                metadatas_to_vectorize.append({
                    "type": "sca",
                    "agent_id": agent_id,
                    "policy_id": policy_id,
                    "score": score,
                    "category": "compliance_audit"
                })

                self.deduplicator.mark_content_as_processed(
                    enriched_text, "sca", {"policy_id": policy_id, "agent_id": agent_id}
                )

        if texts_to_vectorize:
            try:
                vectorstore.add_texts(texts_to_vectorize, metadatas=metadatas_to_vectorize)
                print(f"📥 {len(texts_to_vectorize)} résultats SCA UNIQUES vectorisés")
            except Exception as e:
                print(f"❌ Erreur vectorisation SCA: {e}")

    def log_error(self, source, error_message):
        errors_collection = self.db["errors"]
        errors_collection.insert_one({
            "source": source,
            "error": error_message,
            "timestamp": datetime.now(UTC)
        })
        print(f"⚠️ Erreur enregistrée: {error_message}")

    def add_initial_documentation(self):
        """Version optimisée de la documentation initiale"""
        print("📚 Ajout de documentation technique Wazuh...")

        docs = [
            {
                "text": "Guide d'analyse des tentatives SSH échouées: Les règles Wazuh 5710-5716 détectent les échecs d'authentification SSH. Recherchez les patterns répétitifs depuis une même IP pour identifier les attaques par force brute. Commande utile: grep 'Failed password' /var/log/auth.log",
                "metadata": {"type": "documentation", "topic": "ssh_security", "category": "security_guide"}
            },
            {
                "text": "Classification des niveaux d'alerte Wazuh: Niveau 0-4 (Informationnel), 5-8 (Avertissement), 9-12 (Erreur), 13-15 (Critique). Les alertes de niveau 13+ nécessitent une investigation immédiate. Configurez des notifications automatiques pour ces niveaux.",
                "metadata": {"type": "documentation", "topic": "alert_levels", "category": "configuration"}
            },
            {
                "text": "Surveillance des agents Wazuh: Utilisez 'wazuh-ctl list-agents' pour vérifier l'état des agents. Un agent déconnecté peut indiquer un problème réseau, système arrêté, ou compromission. Vérifiez la connectivité et les logs d'agent.",
                "metadata": {"type": "documentation", "topic": "agent_monitoring", "category": "administration"}
            }
        ]

        texts_to_add, metadatas_to_add = [], []

        for doc in docs:
            if not self.deduplicator.is_content_duplicate(doc["text"], "documentation"):
                texts_to_add.append(doc["text"])
                metadatas_to_add.append(doc["metadata"])
                self.deduplicator.mark_content_as_processed(
                    doc["text"], "documentation", doc["metadata"]
                )

        if texts_to_add:
            try:
                vectorstore.add_texts(texts_to_add, metadatas=metadatas_to_add)
                print(f"✅ Documentation technique ajoutée ({len(texts_to_add)} nouveaux documents)")
            except Exception as e:
                print(f"❌ Erreur ajout documentation: {e}")
        else:
            print("📚 Documentation déjà présente, aucun ajout nécessaire")

    def cleanup_old_data(self):
        """Nettoyage périodique des anciennes données"""
        print("🧹 Nettoyage des données anciennes...")
        self.deduplicator.cleanup_old_hashes(days=30)

        # Optionnel: nettoyer les erreurs anciennes
        cutoff = datetime.now(UTC) - timedelta(days=7)
        result = self.db["errors"].delete_many({"timestamp": {"$lt": cutoff}})
        if result.deleted_count > 0:
            print(f"🧹 {result.deleted_count} anciennes erreurs supprimées")


# === Fonctions API ===
def get_manager_token(db_manager):
    url = f"{MANAGER_API_URL}/security/user/authenticate"
    try:
        response = requests.post(url, auth=(MANAGER_USER, MANAGER_PASSWORD), verify=False)
        response.raise_for_status()
        return response.json()["data"]["token"]
    except requests.exceptions.RequestException as e:
        db_manager.log_error("manager_auth", str(e))
        return None


def get_all_agents(token, db_manager):
    url = f"{MANAGER_API_URL}/agents?offset=0&limit=99999"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json()["data"]["affected_items"]
    except requests.exceptions.RequestException as e:
        db_manager.log_error("manager_agents", str(e))
        return []


def get_syscollector_data(token, agent_id, db_manager):
    headers = {"Authorization": f"Bearer {token}"}
    base_url = f"{MANAGER_API_URL}/syscollector/{agent_id}"

    inventory_data = {
        "agent_id": agent_id,
        "os_info": {},
        "processes": [],
        "ports": [],
        "installed_packages": []
    }

    endpoints = {
        "os_info": f"{base_url}/os",
        "processes": f"{base_url}/processes",
        "ports": f"{base_url}/ports",
        "packages": f"{base_url}/packages"
    }

    for key, url in endpoints.items():
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            data = response.json().get('data', {})

            if key == "os_info":
                inventory_data["os_info"] = data.get("affected_items", [{}])[0]
            else:
                inventory_data[key] = data.get("affected_items", [])
        except requests.exceptions.RequestException as e:
            db_manager.log_error(f"manager_syscollector_{key}_{agent_id}", str(e))

    return inventory_data


def get_agent_vulnerabilities(token, agent_id, db_manager):
    endpoints = [
        f"/vulnerability/{agent_id}",
        f"/vulnerability/{agent_id}/last-scan",
        f"/vulnerability/{agent_id}/results",
        f"/vulnerability-detection/{agent_id}"
    ]

    for endpoint in endpoints:
        url = f"{MANAGER_API_URL}{endpoint}"
        headers = {"Authorization": f"Bearer {token}"}

        try:
            response = requests.get(url, headers=headers, verify=False, timeout=10)

            if response.status_code == 200:
                data = response.json().get('data', {})
                vulns = data.get('affected_items', [])

                if vulns:
                    for v in vulns:
                        v['agent_id'] = agent_id
                    print(f"✅ {len(vulns)} vulnérabilités trouvées via {endpoint}")
                    return vulns
                else:
                    print(f"ℹ️  Aucune vulnérabilité via {endpoint} (données vides)")
                    return []

            elif response.status_code == 404:
                print(f"ℹ️  Endpoint {endpoint} existe mais sans données")
                continue
            else:
                print(f"⚠️  Endpoint {endpoint} - HTTP {response.status_code}")
                continue

        except requests.exceptions.RequestException as e:
            print(f"❌ Erreur connexion sur {endpoint}: {str(e)[:100]}...")
            continue

    print(f"ℹ️  Aucun endpoint vulnérabilité ne retourne de données pour l'agent {agent_id}")
    return []


def get_agent_sca(token, agent_id, db_manager):
    url = f"{MANAGER_API_URL}/sca/{agent_id}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        data = response.json().get('data', {})
        sca_results = data.get('affected_items', [])
        for s in sca_results:
            s['agent_id'] = agent_id
        return sca_results
    except requests.exceptions.RequestException as e:
        db_manager.log_error(f"manager_sca_{agent_id}", str(e))
        return []


def get_indexer_auth_headers():
    auth_string = f"{INDEXER_USER}:{INDEXER_PASSWORD}"
    encoded_auth = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
    return {
        "Content-Type": "application/json",
        "Authorization": f"Basic {encoded_auth}"
    }


def get_alerts_from_indexer(time_range_minutes=120, limit=1000, db_manager=None):
    url = f"{INDEXER_API_URL}/wazuh-alerts-4.x-*/_search"
    headers = get_indexer_auth_headers()
    end_time = datetime.now(UTC).isoformat()[:-10] + 'Z'
    start_time = (datetime.now(UTC) - timedelta(minutes=time_range_minutes)).isoformat()[:-10] + 'Z'

    query = {
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start_time, "lt": end_time
                }
            }
        },
        "size": limit,
        "_source": ["timestamp", "agent.id", "rule", "id", "full_log", "data"]
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(query), verify=False)
        response.raise_for_status()
        return response.json().get('hits', {}).get('hits', [])
    except requests.exceptions.RequestException as e:
        if db_manager:
            db_manager.log_error("indexer_alerts", str(e))
        return []


def run_data_ingestion(db_manager):
    print(f"\n--- Démarrage de la collecte enrichie des données à {datetime.now(UTC)} ---")

    # Ajouter documentation technique initiale si première exécution
    try:
        collection_count = vectorstore._collection.count()
        if collection_count < 5:
            print("📚 Base vectorielle peu fournie, ajout de documentation...")
            db_manager.add_initial_documentation()
    except:
        pass

    # Récupération des données du Manager
    token = get_manager_token(db_manager)
    if token:
        agents = get_all_agents(token, db_manager)
        if agents:
            agents_for_db = [
                {"agent_id": a["id"], "name": a["name"], "os": a.get("os", {}).get("name", "N/A"),
                 "ip": a.get("ip", "N/A"), "status": a["status"], "last_checkin": a.get("lastKeepAlive", "N/A"),
                 "version": a.get("version", "N/A")}
                for a in agents
            ]
            db_manager.insert_agents(agents_for_db)

            syscollector_data = []
            vulnerabilities_data = []
            sca_data = []
            for agent in agents:
                syscollector_result = get_syscollector_data(token, agent["id"], db_manager)
                if syscollector_result: syscollector_data.append(syscollector_result)

                vulns_result = get_agent_vulnerabilities(token, agent["id"], db_manager)
                if vulns_result: vulnerabilities_data.extend(vulns_result)

                sca_result = get_agent_sca(token, agent["id"], db_manager)
                if sca_result: sca_data.extend(sca_result)

            db_manager.insert_syscollector_data(syscollector_data)
            db_manager.insert_vulnerabilities(vulnerabilities_data)
            db_manager.insert_sca_results(sca_data)
        else:
            print("⚠️  Aucun agent récupéré de l'API du Manager.")

    # Récupération des alertes de l'Indexer
    print("\n--- Récupération des alertes de l'Indexer ---")
    raw_alerts = get_alerts_from_indexer(time_range_minutes=120, limit=1000, db_manager=db_manager)

    alerts_for_db = []
    rules_for_db = {}
    if raw_alerts:
        for alert in raw_alerts:
            source = alert["_source"]

            log_details = source.get("data", {})
            alert_doc = {
                "alert_id": source.get("id"),
                "timestamp": source.get("@timestamp") or source.get("timestamp"),
                "ingested_at": datetime.now(UTC),
                "agent_id": source.get("agent", {}).get("id"),
                "rule_id": source.get("rule", {}).get("id"),
                                "rule_description": source.get("rule", {}).get("description"),
                "level": source.get("rule", {}).get("level"),
                "full_log": source.get("full_log"),
                "log": {
                    "event_type": source.get("rule", {}).get("groups", ["N/A"])[0],
                    "source_ip": log_details.get("srcip"),
                    "destination_ip": log_details.get("dstip"),
                    "username": log_details.get("user", {}).get("name") or log_details.get("username")
                }
            }
            alerts_for_db.append(alert_doc)

            rule_id = source.get("rule", {}).get("id")
            if rule_id and rule_id not in rules_for_db:
                rules_for_db[rule_id] = {
                    "rule_id": rule_id,
                    "description": source.get("rule", {}).get("description"),
                    "level": source.get("rule", {}).get("level"),
                    "groups": source.get("rule", {}).get("groups", [])
                }

        db_manager.insert_alerts(alerts_for_db)
        db_manager.insert_rules(list(rules_for_db.values()))
    else:
        print("⚠️  Aucune alerte récente à insérer.")

    # Nettoyage périodique des données anciennes (une fois par jour)
    current_hour = datetime.now(UTC).hour
    if current_hour == 0:  # Exécuter le nettoyage à minuit
        db_manager.cleanup_old_data()

    print(f"\n--- Fin de la collecte enrichie ---")


if __name__ == "__main__":
    print("🚀 Démarrage du collecteur Wazuh ENRICHI avec DÉDUPLICATION")
    validate_env_config()
    db_manager = WazuhDBManager(MONGO_URI, MONGO_DB_NAME)

    while True:
        try:
            run_data_ingestion(db_manager)
        except Exception as e:
            db_manager.log_error("main_loop_error", str(e))
            print(f"❌ Une erreur inattendue est survenue: {e}")

        print("\n😴 En attente de 5 minutes avant la prochaine exécution...")
        time.sleep(300)