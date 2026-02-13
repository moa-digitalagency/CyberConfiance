# CyberConfiance - Guide d'Installation et Déploiement

Ce guide détaille les procédures pour installer, configurer et déployer la plateforme CyberConfiance en local, sur Replit, ou sur un serveur VPS Linux (Ubuntu/Debian).

**Version** : 2.1
**Mise à jour** : 2025

---

## 1. Prérequis Système

*   **Langage** : Python 3.11 ou supérieur.
*   **Base de Données** : PostgreSQL 14+ (recommandé) ou SQLite (dev uniquement).
*   **Système** : Linux (Ubuntu 20.04+, Debian 11+), macOS, ou Windows (via WSL2).
*   **Outils** : `git`, `pip`, `virtualenv` (ou `venv`).
*   **API Keys** :
    *   Have I Been Pwned (HIBP) - Obligatoire pour le Breach Check.
    *   VirusTotal - Obligatoire pour l'Analyseur de Sécurité.

---

## 2. Installation Locale (Développement)

### 2.1. Cloner le Dépôt
```bash
git clone https://github.com/votre-org/CyberConfiance.git
cd CyberConfiance
```

### 2.2. Environnement Virtuel
```bash
python3 -m venv venv
source venv/bin/activate  # Sur Linux/macOS
# ou
venv\Scripts\activate     # Sur Windows
```

### 2.3. Installer les Dépendances
```bash
pip install --upgrade pip
pip install -r requirements.txt
```
*Note : Si l'installation de `psycopg2` échoue, installez les libs système : `sudo apt install libpq-dev`.*

### 2.4. Configuration (.env)
Créez un fichier `.env` à la racine :

```ini
# Base de Données (PostgreSQL Local ou Distant)
DATABASE_URL=postgresql://user:password@localhost:5432/cyberconfiance

# Sécurité (Clés Aléatoires en Prod !)
SECRET_KEY=dev-secret-key-change-me
ADMIN_PASSWORD=MonSuperMotDePasseAdmin!

# APIs Externes
HIBP_API_KEY=votre_cle_api_hibp
SECURITY_ANALYSIS_API_KEY=votre_cle_api_virustotal
# VT_API_KEY= (Alias pour VirusTotal)

# Debug (True en Dev, False en Prod)
FLASK_DEBUG=True
PORT=5000
```

### 2.5. Initialiser la Base de Données
Le script `init_db.py` crée les tables et peuple les données initiales (Règles, Scénarios, Admin par défaut).

```bash
python init_db.py
```
*Vérifiez qu'aucune erreur SQL n'apparaît.*

### 2.6. Lancer l'Application
```bash
python main.py
```
Accédez à `http://localhost:5000`.

---

## 3. Déploiement sur Replit

### 3.1. Importer le Repo
1.  Créez un nouveau Repl "Import from GitHub".
2.  Collez l'URL du dépôt.
3.  Replit détectera automatiquement Python.

### 3.2. Configurer les Secrets
Dans l'onglet "Secrets" (cadenas), ajoutez les variables d'environnement (voir section 2.4).
*   `DATABASE_URL` (Utilisez Neon ou une DB externe).
*   `ADMIN_PASSWORD`
*   `HIBP_API_KEY`
*   `SECURITY_ANALYSIS_API_KEY`
*   `SECRET_KEY`

### 3.3. Lancer
Cliquez sur "Run". Replit installera les paquets et lancera `main.py`.

---

## 4. Déploiement sur VPS (Production - Ubuntu/Debian)

### 4.1. Préparer le Serveur
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3-pip python3-venv postgresql postgresql-contrib nginx git -y
```

### 4.2. Configurer PostgreSQL
```bash
sudo -u postgres psql
postgres=# CREATE DATABASE cyberconfiance;
postgres=# CREATE USER cyberconfiance WITH PASSWORD 'votre_password_db_securise';
postgres=# GRANT ALL PRIVILEGES ON DATABASE cyberconfiance TO cyberconfiance;
postgres=# \q
```

### 4.3. Installer l'Application
```bash
cd /var/www
sudo git clone https://github.com/votre-org/CyberConfiance.git
cd CyberConfiance
sudo chown -R $USER:$USER .

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn  # Serveur WSGI pour la prod
```

### 4.4. Configurer les Variables
Créez `/var/www/CyberConfiance/.env` (voir section 2.4) avec `FLASK_DEBUG=False`.

### 4.5. Initialiser la DB
```bash
python init_db.py
```

### 4.6. Créer le Service Systemd (Gunicorn)
Créez `/etc/systemd/system/cyberconfiance.service` :

```ini
[Unit]
Description=Gunicorn instance to serve CyberConfiance
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/CyberConfiance
Environment="PATH=/var/www/CyberConfiance/venv/bin"
EnvironmentFile=/var/www/CyberConfiance/.env
ExecStart=/var/www/CyberConfiance/venv/bin/gunicorn --workers 3 --bind unix:cyberconfiance.sock -m 007 main:app

[Install]
WantedBy=multi-user.target
```

Activez le service :
```bash
sudo systemctl start cyberconfiance
sudo systemctl enable cyberconfiance
```

### 4.7. Configurer Nginx (Reverse Proxy)
Créez `/etc/nginx/sites-available/cyberconfiance` :

```nginx
server {
    listen 80;
    server_name cyberconfiance.com www.cyberconfiance.com;

    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/CyberConfiance/cyberconfiance.sock;
    }

    location /static {
        alias /var/www/CyberConfiance/static;
        expires 30d;
    }
}
```

Activez le site :
```bash
sudo ln -s /etc/nginx/sites-available/cyberconfiance /etc/nginx/sites-enabled
sudo nginx -t
sudo systemctl restart nginx
```

### 4.8. Sécuriser avec SSL (Certbot)
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d cyberconfiance.com -d www.cyberconfiance.com
```

---

## 5. Maintenance et Mises à Jour

### 5.1. Mettre à Jour le Code
```bash
cd /var/www/CyberConfiance
git pull origin main
source venv/bin/activate
pip install -r requirements.txt  # Si nouvelles dépendances
python init_db.py                # Si nouvelles migrations/seeds
sudo systemctl restart cyberconfiance
```

### 5.2. Voir les Logs
```bash
# Logs Application
sudo journalctl -u cyberconfiance -f

# Logs Nginx (Erreurs Web)
sudo tail -f /var/log/nginx/error.log
```

### 5.3. Sauvegarde Base de Données
```bash
pg_dump -U cyberconfiance cyberconfiance > backup_$(date +%F).sql
```
