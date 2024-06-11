# Utiliser une image Python officielle comme image de base
FROM python:3.9-slim-buster

# Définir le répertoire de travail
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

# Copier les fichiers de configuration et d'installation dans le conteneur
COPY requirements.txt .

# Installer les dépendances du projet
RUN pip install -r requirements.txt

# Copier les fichiers du projet dans le conteneur
COPY . .

# Exposer le port sur lequel l'application s'exécutera
EXPOSE 5000

# Lancer l'application
CMD ["python", "app.py"]
