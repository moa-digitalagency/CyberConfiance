# 🚀 Guide de Déploiement - CyberConfiance

Ce guide vous accompagne pas à pas dans le déploiement de CyberConfiance sur différentes plateformes.

---

## 📋 Pré-requis

### Obligatoires
- ✅ **Compte Have I Been Pwned API** (~$3.50/mois)
  - Inscrivez-vous sur https://haveibeenpwned.com/API/Key
  - La clé API est obligatoire pour la vérification d'emails
  
- ✅ **Compte VirusTotal API** (gratuit avec limite)
  - Créez un compte sur https://www.virustotal.com/
  - Récupérez votre clé API sur https://www.virustotal.com/gui/my-apikey
  - Plan gratuit: 500 requêtes/jour (suffisant pour la plupart des usages)
  - La clé API est obligatoire pour scanner les fichiers/URLs/domaines
  
- ✅ **Base de données PostgreSQL** (production) ou SQLite (développement)

### Recommandés
- ✅ Python 3.11+
- ✅ Serveur compatible WSGI (Gunicorn, uWSGI)
- ✅ Reverse proxy (Nginx, Apache) pour HTTPS

---

## 🔑 Variables d'Environnement

### Variables OBLIGATOIRES

```bash
# Mot de passe administrateur (requis en production)
ADMIN_PASSWORD=VotreMotDePasseSécurisé123!

# Clé API Have I Been Pwned (requis pour vérification d'emails)
HIBP_API_KEY=votre_clé_api_hibp

# Clé API VirusTotal (requis pour scanner fichiers/URLs/domaines)
VT_API_KEY=votre_clé_api_virustotal
```

### Variables RECOMMANDÉES

```bash
# Base de données (PostgreSQL recommandé en production)
DATABASE_URL=postgresql://user:password@host:5432/database_name

# Mode debug (toujours False en production!)
FLASK_DEBUG=False

# Clé secrète pour les sessions Flask
SECRET_KEY=votre_clé_secrète_aléatoire_très_longue

# Port (optionnel, 5000 par défaut)
PORT=5000
```

---

## 🌐 Déploiement sur Replit

### Étape 1: Fork/Import le projet

1. Connectez-vous sur [Replit](https://replit.com)
2. Créez un nouveau Repl Python
3. Importez le code depuis GitHub

### Étape 2: Configuration des Secrets

1. Allez dans l'onglet **"Secrets"** (🔒 dans la sidebar)
2. Ajoutez les variables suivantes:

```
ADMIN_PASSWORD = VotreMotDePasseSécurisé123!
HIBP_API_KEY = votre_clé_api_hibp
```

### Étape 3: Installation des dépendances

Les dépendances s'installent automatiquement. Si nécessaire, manuellement:

```bash
pip install -r requirements.txt
```

### Étape 4: Initialisation de la base de données

L'application initialise automatiquement la base de données au démarrage.
Pour réinitialiser manuellement:

```bash
python init_db.py --reset  # ⚠️ SUPPRIME toutes les données!
```

### Étape 5: Lancer l'application

**En développement:**
```bash
python main.py
```

**En production (Replit Deployments):**
1. Cliquez sur "Deploy"
2. Configurez les Deployment Secrets (ADMIN_PASSWORD, HIBP_API_KEY)
3. Déployez

L'application utilise automatiquement Gunicorn en production.

---

## 🐳 Déploiement avec Docker (Optionnel)

### Créer un Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Variables d'environnement par défaut
ENV FLASK_DEBUG=False
ENV PORT=5000

# Exposer le port
EXPOSE 5000

# Commande de démarrage
CMD ["gunicorn", "--bind=0.0.0.0:5000", "--reuse-port", "--workers=2", "main:app"]
```

### Docker Compose avec PostgreSQL

```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://cyberconf:password@db:5432/cyberconfiance
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - HIBP_API_KEY=${HIBP_API_KEY}
      - FLASK_DEBUG=False
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=cyberconf
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=cyberconfiance
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres_data:
```

**Démarrer:**
```bash
docker-compose up -d
```

---

## ☁️ Déploiement sur Heroku

### Étape 1: Préparer l'application

Créez un fichier `Procfile`:
```
web: gunicorn --bind=0.0.0.0:$PORT --reuse-port --workers=2 main:app
```

### Étape 2: Créer l'application Heroku

```bash
heroku create votre-app-cyberconfiance
```

### Étape 3: Ajouter PostgreSQL

```bash
heroku addons:create heroku-postgresql:mini
```

### Étape 4: Configurer les variables

```bash
heroku config:set ADMIN_PASSWORD="VotreMotDePasseSécurisé123!"
heroku config:set HIBP_API_KEY="votre_clé_api_hibp"
heroku config:set FLASK_DEBUG="False"
```

### Étape 5: Déployer

```bash
git push heroku main
```

### Étape 6: Initialiser la base de données

```bash
heroku run python init_db.py
```

---

## 🖥️ Déploiement sur VPS (Linux)

### Prérequis
- Ubuntu 22.04+ ou Debian 11+
- Python 3.11+
- PostgreSQL
- Nginx
- Systemd

### Étape 1: Installation des dépendances

```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip postgresql nginx
```

### Étape 2: Configuration de PostgreSQL

```bash
sudo -u postgres psql

CREATE DATABASE cyberconfiance;
CREATE USER cyberconf WITH PASSWORD 'votre_mot_de_passe';
GRANT ALL PRIVILEGES ON DATABASE cyberconfiance TO cyberconf;
\q
```

### Étape 3: Cloner et configurer l'application

```bash
cd /var/www
sudo git clone https://github.com/votre-repo/cyberconfiance.git
cd cyberconfiance

# Créer un environnement virtuel
sudo python3.11 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt
```

### Étape 4: Variables d'environnement

Créez `/var/www/cyberconfiance/.env`:
```bash
DATABASE_URL=postgresql://cyberconf:votre_mot_de_passe@localhost:5432/cyberconfiance
ADMIN_PASSWORD=VotreMotDePasseSécurisé123!
HIBP_API_KEY=votre_clé_api_hibp
FLASK_DEBUG=False
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
```

### Étape 5: Initialiser la base de données

```bash
source venv/bin/activate
python init_db.py
```

### Étape 6: Configuration Systemd

Créez `/etc/systemd/system/cyberconfiance.service`:

```ini
[Unit]
Description=CyberConfiance Web Application
After=network.target postgresql.service

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/var/www/cyberconfiance
Environment="PATH=/var/www/cyberconfiance/venv/bin"
EnvironmentFile=/var/www/cyberconfiance/.env
ExecStart=/var/www/cyberconfiance/venv/bin/gunicorn \
    --bind=127.0.0.1:5000 \
    --workers=4 \
    --reuse-port \
    --timeout=60 \
    --access-logfile=/var/log/cyberconfiance/access.log \
    --error-logfile=/var/log/cyberconfiance/error.log \
    main:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Créer le dossier de logs:
```bash
sudo mkdir -p /var/log/cyberconfiance
sudo chown www-data:www-data /var/log/cyberconfiance
```

Activer et démarrer:
```bash
sudo systemctl enable cyberconfiance
sudo systemctl start cyberconfiance
sudo systemctl status cyberconfiance
```

### Étape 7: Configuration Nginx

Créez `/etc/nginx/sites-available/cyberconfiance`:

```nginx
server {
    listen 80;
    server_name votre-domaine.com www.votre-domaine.com;

    # Redirection HTTPS (après configuration SSL)
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name votre-domaine.com www.votre-domaine.com;

    # Certificat SSL (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/votre-domaine.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/votre-domaine.com/privkey.pem;
    
    # Configuration SSL recommandée
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /static {
        alias /var/www/cyberconfiance/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Activer et redémarrer Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/cyberconfiance /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Étape 8: SSL avec Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d votre-domaine.com -d www.votre-domaine.com
sudo systemctl reload nginx
```

---

## 🔒 Sécurité Post-Déploiement

### Checklist de sécurité

- [ ] ✅ Changez le mot de passe admin par défaut
- [ ] ✅ Configurez `ADMIN_PASSWORD` différent de `admin123`
- [ ] ✅ Vérifiez que `FLASK_DEBUG=False` en production
- [ ] ✅ Utilisez HTTPS (certificat SSL)
- [ ] ✅ Configurez un firewall (UFW sur Ubuntu)
- [ ] ✅ Mettez à jour régulièrement les dépendances
- [ ] ✅ Activez les sauvegardes automatiques de la base
- [ ] ✅ Surveillez les logs d'erreur et de sécurité
- [ ] ✅ Limitez l'accès SSH (clés uniquement)
- [ ] ✅ Configurez fail2ban pour bloquer les attaques par force brute

### Firewall UFW (Ubuntu)

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

### Sauvegardes PostgreSQL

Créez un script de sauvegarde `/var/backups/backup_cyberconfiance.sh`:
```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/cyberconfiance"
mkdir -p $BACKUP_DIR

pg_dump cyberconfiance | gzip > $BACKUP_DIR/backup_$DATE.sql.gz

# Garder seulement les 30 dernières sauvegardes
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +30 -delete
```

Automatiser avec cron:
```bash
sudo crontab -e
# Ajouter: Sauvegarde quotidienne à 3h du matin
0 3 * * * /var/backups/backup_cyberconfiance.sh
```

---

## 📊 Monitoring et Logs

### Consulter les logs

**Application:**
```bash
# Systemd logs
sudo journalctl -u cyberconfiance -f

# Logs Gunicorn
sudo tail -f /var/log/cyberconfiance/access.log
sudo tail -f /var/log/cyberconfiance/error.log
```

**Nginx:**
```bash
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### Vérifier le statut

```bash
# Application
sudo systemctl status cyberconfiance

# Nginx
sudo systemctl status nginx

# PostgreSQL
sudo systemctl status postgresql
```

---

## 🔄 Mise à jour

### Mise à jour du code

```bash
cd /var/www/cyberconfiance
sudo git pull origin main
source venv/bin/activate
pip install -r requirements.txt

# Redémarrer l'application
sudo systemctl restart cyberconfiance
```

### Mise à jour de la base de données

Si les modèles ont changé:
```bash
python init_db.py  # Ajoute les nouvelles données
# OU
python init_db.py --reset  # ⚠️ Réinitialise complètement
```

---

## ❓ Dépannage

### L'application ne démarre pas

1. Vérifiez les logs:
```bash
sudo journalctl -u cyberconfiance -n 50
```

2. Vérifiez les variables d'environnement:
```bash
python check_env.py
```

3. Vérifiez la connexion à la base de données:
```bash
psql -U cyberconf -d cyberconfiance -h localhost
```

### Erreur de connexion à la base de données

```bash
# Vérifier que PostgreSQL est démarré
sudo systemctl status postgresql

# Tester la connexion
psql -U cyberconf -d cyberconfiance -h localhost
```

### Erreur 502 Bad Gateway (Nginx)

```bash
# Vérifier que l'application tourne
sudo systemctl status cyberconfiance

# Vérifier les logs Nginx
sudo tail -f /var/log/nginx/error.log
```

---

## 📞 Support

Pour toute question ou problème:
- **Email:** admin@cyberconfiance.fr
- **Documentation:** [README.md](README.md)
- **Vérification:** [check_env.py](check_env.py)

---

**CyberConfiance - Votre bouclier numérique** 🛡️
