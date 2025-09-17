# SOC ChatBot Assistant

## Table des matières
1.  [Introduction](#1-introduction)
2.  [Architecture](#2-architecture)
3.  [Fonctionnement Détaillé](#3-fonctionnement-détaillé)
4.  [Bénéfices Clés](#4-bénéfices-clés)
5.  [Fonctionnalités](#5-fonctionnalités)
6.  [Prérequis](#6-prérequis)
7.  [Configuration du Projet](#7-configuration-du-projet)
    *   [Cloner le Dépôt](#cloner-le-dépôt)
    *   [Configuration des Variables d'Environnement](#configuration-des-variables-denvironnement)
    *   [Construction des Images Docker](#construction-des-images-docker)
    *   [Lancement des Services](#lancement-des-services)
8.  [Accès à l'Application](#8-accès-à-lapplication)
9.  [Identifiants par Défaut](#9-identifiants-par-défaut)
10. [Structure du Projet](#10-structure-du-projet)
11. [Dépannage Courant](#11-dépannage-courant)
    *   [Problèmes avec l'API Gemini](#problèmes-avec-lapi-gemini)
    *   [Frontend affiche une page blanche ou "Cette page ne fonctionne pas"](#frontend-affiche-une-page-blanche-ou-cette-page-ne-fonctionne-pas)
    *   [MongoDB "unhealthy"](#mongodb-unhealthy)
    *   [Erreurs de permissions SQLite du Backend](#erreurs-de-permissions-sqlite-du-backend)
    *   [Temps de construction lents](#temps-de-construction-lents)
12. [Améliorations Futures](#12-améliorations-futures)

---

## 1. Introduction

Ce projet implémente un **Assistant ChatBot pour un Centre d'Opérations de Sécurité (SOC)**, conçu pour transformer la manière dont les analystes interagissent avec les données de sécurité. Face à la surcharge d'informations et à la complexité des requêtes manuelles, notre solution offre une interface conversationnelle intuitive, propulsée par l'intelligence artificielle (Google Gemini) et enrichie par une base de connaissances vectorielle (ChromaDB) et une analyse structurée des données (MongoDB Wazuh).

L'objectif est d'accélérer significativement l'analyse des incidents, d'améliorer la corrélation d'événements et de fournir des réponses actionnables en temps réel, renforçant ainsi la posture de sécurité globale.

## 2. Architecture

L'application est conteneurisée et orchestrée par Docker Compose, comprenant les services et technologies clés suivants :

*   **`mongodb` (Base de Données NoSQL)**: Stocke les alertes, les informations d'agents et les résultats d'audit collectés depuis Wazuh. Permet une grande flexibilité et scalabilité pour les données non structurées de sécurité.
*   **`data_collector` (Python, Langchain, sentence-transformers, ChromaDB)**: Un service Python essentiel qui ingère les données de Wazuh dans MongoDB et construit la base de données vectorielle ChromaDB. Il utilise `sentence-transformers` pour créer des embeddings sémantiques des données de sécurité, permettant une recherche de contexte avancée pour la RAG.
*   **`backend` (Flask, Python, Google Gemini API, Langchain, CrossEncoder)**: L'API principale qui orchestre l'intelligence du système. Elle gère l'authentification, reçoit les requêtes du frontend, interagit avec MongoDB pour les données brutes, utilise ChromaDB pour le RAG (avec un `CrossEncoder` pour le re-ranking), et envoie les prompts enrichis à l'API Google Gemini pour la génération de réponses intelligentes et structurées.
*   **`frontend` (React.js, Vite, Tailwind CSS, Nginx)**: L'interface utilisateur moderne et réactive qui offre une expérience de chat intuitive, un tableau de bord de supervision et un historique des conversations. Développé avec React.js et Vite pour des performances élevées, stylisé avec Tailwind CSS, et servi en production par un conteneur Nginx optimisé pour les applications SPA.

## 3. Fonctionnement Détaillé

Ce système est conçu pour optimiser l'analyse des données de sécurité Wazuh grâce à l'intégration de bases de données (MongoDB, ChromaDB) et de l'intelligence artificielle (Google Gemini).

### Flux de Données

1.  **Collecte (Service `data_collector`)**:
    *   Le `data_collector` se connecte aux APIs de Wazuh Manager et Indexer.
    *   Il récupère les alertes et les informations des agents.
    *   Ces données sont stockées dans **MongoDB**.
    *   Simultanément, le collecteur traite le contenu textuel des alertes pour créer des **embeddings** (représentations vectorielles).
    *   Ces embeddings sont ensuite stockés dans la base de données vectorielle **ChromaDB**, qui se trouve dans un volume partagé (`./data_collecte/chroma_db`).

2.  **Traitement et Analyse (Service `backend`)**:
    *   Lorsqu'un utilisateur soumet une question via le frontend, le `backend` (application Flask) reçoit cette requête.
    *   Il effectue une **recherche hybride** :
        *   **Recherche structurée dans MongoDB** : En fonction de la question, il exécute des requêtes spécifiques pour extraire des alertes, des statuts d'agents, des logs d'authentification, etc.
        *   **Recherche contextuelle avec RAG (Retrieval Augmented Generation)** : La question est utilisée pour interroger **ChromaDB**. Cela permet de récupérer des documents de documentation ou des extraits pertinents qui sont sémantiquement proches de la question.
            *   Un **re-ranker** (`CrossEncoder`) est utilisé pour affiner les résultats du RAG, en sélectionnant les documents les plus pertinents parmi une liste plus large.
    *   Le `backend` agrège ensuite ces informations (données MongoDB, contexte RAG, résumé système) dans un **prompt optimisé**.
    *   Ce prompt est envoyé à l'**API Google Gemini** pour générer une réponse.
    *   La réponse générée est formatée de manière structurée pour être facilement consommée par le frontend.

### Intégration de l'IA (Gemini)

Le `backend` communique avec l'API Gemini (`gemini-1.5-flash`) pour obtenir des analyses et des réponses. Plusieurs stratégies sont mises en œuvre pour optimiser cette interaction, garantissant robustesse et pertinence :

*   **Prompt Engineering Avancé** : Le prompt est méticuleusement conçu pour guider Gemini. Il inclut des instructions claires sur son rôle d'analyste SOC expert, le format de réponse attendu, et les données contextuelles disponibles. Cela maximise la qualité et la pertinence des réponses.
*   **Gestion Dynamique des Limites et Priorités** : Le système adapte intelligemment la quantité de données passées à Gemini en fonction de la complexité de la requête et des limites configurées. Les requêtes urgentes peuvent recevoir une allocation de ressources accrue, permettant des analyses plus profondes.
*   **Mécanisme de Retry Intelligent et Compression de Prompt** : En cas de surcharge de l'API (`429 Rate Limit`) ou d'indisponibilité du service, le système implémente une stratégie de retry avec délai exponentiel. Si le prompt est trop long, il est compressé intelligemment pour réduire sa taille tout en préservant les informations essentielles, augmentant ainsi les chances de succès de la requête.
*   **Réponses de Fallback Informatives** : Si Gemini ne peut pas générer de réponse après plusieurs tentatives, un message de fallback détaillé et actionnable est fourni à l'utilisateur, évitant ainsi des blocages complets.

### RAG (Retrieval Augmented Generation)

Le processus de RAG est essentiel pour fournir des réponses précises et basées sur des faits, en utilisant votre propre base de connaissances sur Wazuh et les données spécifiques du SOC. Il fonctionne comme suit :

1.  **Embeddings Sémantiques** : La documentation Wazuh et les données de sécurité pertinentes sont transformées en représentations numériques de haute dimension (embeddings) à l'aide de `sentence-transformers`.
2.  **Indexation Vectorielle** : Ces embeddings sont stockés et indexés efficacement dans **ChromaDB**, une base de données vectorielle optimisée pour les recherches de similarité.
3.  **Recherche de Similarité** : Lorsqu'une question est posée par l'utilisateur, elle est également convertie en embedding. ChromaDB est ensuite interrogée pour trouver les documents (documentation ou données brutes) dont les embeddings sont les plus similaires à ceux de la question de l'utilisateur. Ces documents sont considérés comme un contexte pertinent.
4.  **Re-ranking Intelligent** : Pour améliorer la qualité et la pertinence du contexte récupéré, un modèle `CrossEncoder` est utilisé. Ce modèle évalue la relation entre la question et chaque document récupéré, en attribuant un score de pertinence. Seuls les documents les plus pertinents (ceux avec les scores les plus élevés) sont conservés et inclus dans le prompt envoyé à Gemini.
5.  **Génération Augmentée et Ancrée** : Gemini reçoit la question de l'utilisateur *plus* le contexte factuel et pertinent extrait via RAG. Cela permet à Gemini de générer une réponse non seulement créative et utile, mais aussi factuellement ancrée dans les données spécifiques de votre SOC et votre documentation.

## 4. Bénéfices Clés

Ce SOC ChatBot Assistant apporte une valeur significative aux analystes et aux opérations de sécurité :

*   **Accélération de l'Analyse et de la Réponse aux Incidents (MTTD/MTTR)** : En permettant des requêtes en langage naturel, le ChatBot réduit le temps nécessaire pour obtenir des informations critiques, accélérant ainsi la détection (Mean Time To Detect) et la réponse (Mean Time To Respond) aux incidents.
*   **Démocratisation de l'Accès aux Données de Sécurité** : Les analystes de tous niveaux peuvent interroger des systèmes complexes comme Wazuh et MongoDB sans maîtriser des syntaxes de requête spécifiques (KQL, MQL), rendant les informations plus accessibles.
*   **Insights Améliorés et Corrélation Intelligente** : L'intégration de Gemini et du RAG permet de corréler des événements provenant de différentes sources et de dégager des tendances ou des schémas d'attaque complexes, fournissant des perspectives plus profondes que les outils traditionnels.
*   **Réduction de la Charge Cognitive et Automatisation Partielle** : Les tâches répétitives de recherche et de synthèse sont prises en charge par l'IA, libérant ainsi les analystes pour se concentrer sur des enquêtes plus complexes et des décisions stratégiques.
*   **Rapports et Synthèses Rapides** : Le ChatBot peut générer des synthèses d'événements, des statuts d'agents ou des rapports de conformité en quelques secondes, facilitant la communication et le reporting au sein de l'équipe SOC.

## 5. Fonctionnalités

*   **Collecte de Données Wazuh**: Récupération automatique des alertes et informations d'agents depuis les APIs Wazuh.
*   **Analyse de Sécurité par IA**: Utilisation de l'API Google Gemini pour analyser les questions des utilisateurs et générer des réponses pertinentes basées sur les données collectées.
*   **Retrieval Augmented Generation (RAG)**: Intégration de ChromaDB et de `sentence-transformers` pour enrichir les réponses de l'IA avec des documents de sécurité pertinents.
*   **Tableau de Bord SOC**: Visualisation des métriques clés de sécurité (nombre d'alertes, statut des agents, etc.).
*   **Historique des Conversations**: Suivi des interactions avec le ChatBot.
*   **Authentification Utilisateur**: Système de connexion pour les analystes et administrateurs.

## 6. Prérequis

Avant de commencer, assurez-vous d'avoir installé les éléments suivants sur votre système :

*   **Docker**: [Instructions d'installation Docker](https://docs.docker.com/get-docker/)
*   **Docker Compose**: Généralement inclus avec Docker Desktop. Si non, [instructions d'installation Docker Compose](https://docs.docker.com/compose/install/)
*   **Clé API Google Gemini**: Vous aurez besoin d'une clé API pour l'IA Gemini. Vous pouvez l'obtenir via [Google AI Studio](https://ai.google.dev/).
*   **Accès à un serveur Wazuh**: Les services `data_collector` et `backend` sont configurés pour interagir avec une instance Wazuh (Manager et Indexer). Assurez-vous d'avoir les URLs et identifiants corrects.

## 7. Configuration du Projet

### Cloner le Dépôt

```bash
git clone <URL_DE_VOTRE_DEPOT>
cd projet_stage
```

### Configuration des Variables d'Environnement

Créez un fichier `.env` à la racine du projet (`projet_stage/.env`) et remplissez-le avec vos variables d'environnement. Ces variables seront utilisées par Docker Compose pour configurer les services.

Exemple de `.env` :

```env
# Variables pour l'API Gemini
GEMINI_API_KEY=VOTRE_CLE_API_GEMINI

# Variables pour l'authentification Flask (Backend)
FLASK_SECRET_KEY=UNE_CLE_SECRETE_FORTE_POUR_FLASK

# Variables pour l'accès aux APIs Wazuh (Manager et Indexer)
WAZUH_MANAGER_PASSWORD=VOTRE_WAZUH_MANAGER_PASSWORD
WAZUH_INDEXER_PASSWORD=VOTRE_WAZUH_INDEXER_PASSWORD
```

**ATTENTION :** Remplacez les valeurs `VOTRE_...` par vos propres clés et mots de passe. Ne partagez jamais votre clé API Gemini ou vos mots de passe Wazuh.

### Construction des Images Docker

Naviguez jusqu'au répertoire racine de votre projet (`projet_stage`).
Pour construire toutes les images des services (cela peut prendre un certain temps la première fois) :

```bash
docker-compose build --no-cache
```

Si vous modifiez un `Dockerfile`, il est recommandé d'utiliser l'option `--no-cache` pour s'assurer que la nouvelle image est construite à partir de zéro.

### Lancement des Services

Après la construction, lancez tous les services en arrière-plan :

```bash
docker-compose up -d
```

Pour arrêter les services :

```bash
docker-compose down
```

Pour voir les logs de tous les services :

```bash
docker-compose logs -f
```

## 8. Accès à l'Application

Une fois tous les services démarrés, vous pouvez accéder à l'application frontend via votre navigateur web :

*   **Frontend**: `http://localhost:3000`
*   **Backend API**: `http://localhost:5000` (pour les appels API, non directement accessible via le navigateur)

## 9. Identifiants par Défaut

Le service `backend` initialise une base de données SQLite avec des utilisateurs par défaut si elle n'existe pas :

*   **Administrateur**:
    *   Nom d'utilisateur: `admin`
    *   Mot de passe: `admin123`
*   **Analyste**:
    *   Nom d'utilisateur: `analyst`
    *   Mot de passe: `analyst123`

Il est fortement recommandé de changer ces mots de passe après la première connexion pour des raisons de sécurité.

## 10. Structure du Projet

```
projet_stage/
├── docker-compose.yml              # Configuration des services Docker
├── .env                            # Variables d'environnement (à créer manuellement)
├── backend/
│   ├── Dockerfile                  # Dockerfile pour le service backend
│   ├── app.py                      # Application Flask principale
│   ├── requirements.txt            # Dépendances Python du backend
│   ├── .dockerignore               # Fichiers à ignorer par Docker pour le backend
│   ├── wazuh_hybrid_system.py      # Logique métier pour l'intégration Wazuh et IA
│   ├── soc_chatbot.db              # Base de données SQLite (générée, volume monté)
│   ├── __pycache__/                # Cache Python
│   ├── chroma_db/                  # Base de données vectorielle (ChromaDB)
│   └── config/                     # Fichiers de configuration spécifiques au backend
├── data_collecte/
│   ├── Dockerfile                  # Dockerfile pour le collecteur de données
│   ├── .dockerignore               # Fichiers à ignorer par Docker pour le collecteur
│   ├── data_collecter_v2.py        # Script de collecte de données Wazuh
│   ├── requirements.txt            # Dépendances Python du collecteur
│   └── chroma_db/                  # Base de données vectorielle (ChromaDB)
└── frontend/
    ├── Dockerfile                  # Dockerfile pour l'application React/Vite
    ├── .dockerignore               # Fichiers à ignorer par Docker pour le frontend
    ├── index.html                  # Fichier HTML principal
    ├── package.json                # Dépendances Node.js du frontend
    ├── vite.config.js              # Configuration de Vite
    ├── src/                        # Code source React
    │   ├── App.jsx
    │   ├── main.jsx
    │   └── components/             # Composants React
    ├── public/                     # Assets statiques (si présents)
    └── node_modules/               # Dépendances Node.js (ignoré par Docker)
```

## 11. Dépannage Courant

### Problèmes avec l'API Gemini

Si vous voyez `⚠️ Service indisponible, retry X/3` dans les logs du `backend` :
1.  **Vérifiez `GEMINI_API_KEY`**: Assurez-vous que la clé dans votre `.env` est correcte et active.
2.  **Connectivité réseau**: Vérifiez que votre conteneur `backend` peut accéder à `generativelanguage.googleapis.com`. Un pare-feu sur votre machine hôte peut bloquer le trafic sortant.
3.  **Statut de l'API Google**: Consultez la page d'état de Google Cloud pour d'éventuels incidents.

### Frontend affiche une page blanche ou "Cette page ne fonctionne pas"

1.  **Redémarrez les services**: Assurez-vous d'avoir exécuté `docker-compose build frontend` puis `docker-compose up -d` après toute modification du `frontend/Dockerfile` ou du code React.
2.  **Vérifiez les logs Nginx**: Accédez aux logs du conteneur `frontend` (`docker-compose logs frontend`) pour voir si Nginx rencontre des erreurs de démarrage ou de service de fichiers.
3.  **Console du navigateur**: Ouvrez les outils de développement de votre navigateur (F12) et vérifiez les onglets "Console" et "Réseau" pour des erreurs JavaScript ou des échecs de chargement de ressources.

### MongoDB "unhealthy"

Si le service `mongodb` reste en statut `unhealthy` :
1.  **Temps de démarrage**: MongoDB peut prendre du temps à démarrer. Les paramètres `start_period`, `timeout`, `retries` dans `docker-compose.yml` ont été ajustés, mais si votre machine est lente, vous pourriez avoir besoin de les augmenter encore.
2.  **Commande de healthcheck**: La commande `["CMD", "mongosh", "--eval", "db.adminCommand('ping').ok"]` nécessite `mongosh` à l'intérieur du conteneur. Assurez-vous que l'image `mongo:latest` inclut bien `mongosh` (ce qui est le cas normalement).

### Erreurs de permissions SQLite du Backend

Si le `backend` ne peut pas écrire dans `soc_chatbot.db` :
1.  Assurez-vous que le volume `backend_db_data` est correctement monté dans `docker-compose.yml` (`- backend_db_data:/app/database_data`).
2.  Le `backend/Dockerfile` inclut des commandes `mkdir -p /app/database_data` et `chown -R appuser:appuser /app` pour garantir les permissions. Reconstruisez le backend si vous avez eu des problèmes à ce niveau.

### Temps de construction lents

Si la construction d'une image est trop lente :
1.  **Utilisez `.dockerignore`**: Assurez-vous que les répertoires inutiles comme `node_modules/` et `venv/` sont listés dans les fichiers `.dockerignore` correspondants pour chaque service afin de réduire le contexte de construction.
2.  **Optimisation des couches**: Regroupez les commandes `RUN` dans le `Dockerfile` (par exemple, `apt-get update && apt-get install -y ...`) pour réduire le nombre de couches.
3.  **Mise en cache**: Docker met en cache les couches. Si vous modifiez une étape tôt dans le `Dockerfile`, les étapes suivantes devront être reconstruites.

## 12. Améliorations Futures

*   **Intégration Wazuh API complète**: Étendre la collecte et l'interrogation pour couvrir plus d'endpoints Wazuh.
*   **Personnalisation de l'IA**: Permettre la configuration des paramètres de l'IA (modèle, température) via l'interface utilisateur.
*   **Notifications**: Implémenter des notifications pour les alertes critiques.
*   **Thèmes Frontend**: Ajouter des options de thème clair/sombre.
*   **Test Unitaires et d'Intégration**: Ajouter des tests pour tous les services.
*   **CI/CD**: Mettre en place un pipeline d'intégration et de déploiement continus.
