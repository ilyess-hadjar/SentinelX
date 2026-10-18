# SentinelX — File Integrity Monitor



**Outil de surveillance de l’intégrité des fichiers développé en Python.**



SentinelX est un projet personnel orienté cybersécurité conçu pour détecter les changements affectant un ensemble de fichiers à partir de leurs empreintes cryptographiques SHA-256.



L’objectif est de disposer d’un outil permettant de surveiller un dossier, de comparer son état à une référence et de consulter l’historique des événements.



## Fonctionnalités



- **Empreintes SHA-256** pour contrôler l’intégrité des fichiers.

- **Référence d’intégrité initiale** pour établir un état de référence.

- **Détection des changements** lors des analyses.

- **Surveillance périodique** avec un intervalle configurable.

- **Historique des événements** stocké localement.

- **Export des données** aux formats JSON et CSV.

- **Interface graphique** avec tableau de bord.

- **Notifications Windows** pour signaler certains événements.

- **Tests automatisés** pour vérifier le comportement du programme.



## Technologies utilisées



- Python

- SHA-256

- CustomTkinter

- Matplotlib

- Watchdog

- SQLite

- Pytest



## Prérequis



- Windows

- Python installé

- `pip` disponible



## Installation



Clonez le dépôt, puis placez-vous dans le dossier du projet :



```powershell

git clone <URL\_DU\_DEPOT>

cd <DOSSIER\_DU\_DEPOT>

```



Installez les dépendances :



```powershell

python -m pip install -r requirements.txt

```



Remplacez les valeurs entre chevrons par l’URL et le nom réels du dépôt une fois celui-ci publié.



## Utilisation en ligne de commande



Afficher l’aide :



```powershell

python main.py --help

```



Initialiser une référence d’intégrité :



```powershell

python main.py "C:\\chemin\\vers\\dossier" --init-baseline

```



Surveiller un dossier avec un intervalle personnalisé :



```powershell

python main.py "C:\\chemin\\vers\\dossier" --interval 60

```



Accepter des changements après vérification :



```powershell

python main.py "C:\\chemin\\vers\\dossier" --accept-changes

```



Exporter l’historique :



```powershell

python main.py --export

```



Les chemins et options doivent être adaptés à l’environnement d’exécution. Vérifiez toujours l’aide de la version installée avant utilisation.



## Interface graphique



Le projet inclut un tableau de bord graphique. Pour le lancer depuis le dossier du projet :



```powershell

python dashboard.py

```



## Tests



Les tests automatisés sont exécutés avec Pytest.



Depuis le dossier racine du dépôt :



```powershell

$env:PYTHONPATH = (Get-Location).Path
python -m pytest tests -q

```



**État de validation :** 22 tests réussis lors de la dernière vérification locale.



## Sécurité et données locales



Les clés de signature, les références d’intégrité, les bases de données et les rapports générés peuvent contenir des données propres à l’environnement local. Ils doivent être examinés avant toute publication.



Ne publiez jamais de clé privée, de secret ou de donnée personnelle dans le dépôt.



## Objectifs du projet



Ce projet me permet de mettre en pratique des notions liées à la cybersécurité :



- intégrité et empreintes cryptographiques ;

- surveillance de fichiers ;

- journalisation et traçabilité ;

- automatisation en Python ;

- tests et validation ;

- gestion de versions avec Git.



## Auteur



Projet personnel réalisé dans le cadre de mon apprentissage de la programmation et de la cybersécurité.




