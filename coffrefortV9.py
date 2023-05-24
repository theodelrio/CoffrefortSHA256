import base64
import getpass
import uuid
import pickle
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def save_passwords_to_storage(passwords):
    with open("password_storage.pickle", "wb") as file:
        # Sérialise le dictionnaire et l'écrit dans le fichier
        pickle.dump(passwords, file)


def load_passwords_from_storage():
    try:
        with open("password_storage.pickle", "rb") as file:
            # Désérialise le dictionnaire à partir du fichier
            passwords = pickle.load(file)
        return passwords
    except FileNotFoundError:
        print("Le fichier de stockage des mots de passe n'a pas été trouvé.")
        return {}

def save_key_to_file(key):
    with open("key_file.pickle", "wb") as file:
        # Sérialise la clé et l'écrit dans le fichier
        pickle.dump(key, file)

def load_key_from_file():
    try:
        with open("key_file.pickle", "rb") as file:
            # Désérialise la clé à partir du fichier
            key = pickle.load(file)
        return key
    except FileNotFoundError:
        return None


# Défini la variable en dictionnaire
passwords = {}

if not os.path.exists("password_storage.pickle"):
    # Crée le fichier s'il n'existe pas
    with open("password_storage.pickle", "wb") as file:
        # Crée un dictionnaire vide et l'écrit dans le fichier
        pickle.dump({}, file)






#############################################################

# Charge la clé de chiffrement depuis le fichier s'il existe
key = load_key_from_file()
fernet = Fernet(key)
# Défini la variable en dictionnaire
passwords = {}

if not os.path.exists("password_storage.pickle"):
    # Crée le fichier s'il n'existe pas
    with open("password_storage.pickle", "wb") as file:
        # Crée un dictionnaire vide et l'écrit dans le fichier
        pickle.dump({}, file)
        
# Demande à l'utilisateur de saisir le mot de passe d'accès
password = getpass.getpass("Entrez le mot de passe du coffre-fort (minimum 6 caractères) : ")

# Vérifie si le mot de passe a au moins 6 caractères
while len(password) < 6:
    print("Le mot de passe doit avoir au moins 6 caractères.")
    password = getpass.getpass("Entrez le mot de passe du coffre-fort (minimum 6 caractères) : ")

# Encode le mot de passe en utf-8
password_bytes = password.encode("utf-8")

# Dérive une clé de chiffrement à partir du mot de passe en utilisant l'algorithme PBKDF2
# Utilise un sel aléatoire pour renforcer la sécurité de la clé de chiffrement
salt = uuid.uuid4().bytes
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)

# Si la clé n'est pas présente dans le fichier, la dérive à partir du mot de passe
if key is None:
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    # Crée un objet Fernet à partir de la clé dérivée
    fernet = Fernet(key)

    # Charge les mots de passe enregistrés depuis le fichier
    passwords = load_passwords_from_storage()








#################################################################





    # Demande à l'utilisateur ce qu'il souhaite faire
    #action = input("Voulez-vous (E)ntrer un nouveau mot de passe, (L)ire un mot de passe existant, (Q)uitter le programme et sauvegarder l'état du coffre-fort ou (QQ)uitter le programme sans sauvegarder l'état du coffre-fort ? ")

while True:
        # Demande à l'utilisateur ce qu'il souhaite faire
        action = input("Voulez-vous (E)ntrer un nouveau mot de passe, (L)ire un mot de passe existant, (Q)uitter le programme et sauvegarder l'état du coffre-fort ou (QQ)uitter le programme sans sauvegarder l'état du coffre-fort ? ")


        if action.lower() == "e":
            # Demande à l'utilisateur de saisir un mot de passe à ajouter au coffre-fort
            password = getpass.getpass("Entrez un mot de passe à ajouter au coffre-fort : ")

            # Demande à l'utilisateur de saisir le nom du site internet associé au mot de passe
            site_name = input("Entrez le nom du site internet associé au mot de passe : ")

            # Vérifie si le nom du site internet est déjà présent dans le dictionnaire
            if site_name in passwords:
                # Demande à l'utilisateur s'il souhaite remplacer le mot de passe existant
                replace = input("Un mot de passe existe déjà pour ce site internet. Voulez-vous le remplacer ? (o/n) ")
                if replace.lower() == "n":
                    continue

            # Encode le mot de passe en utf-8
            password_bytes = password.encode("utf-8")

            # Chiffre le mot de passe en utilisant l'objet Fernet
            encrypted_password = fernet.encrypt(password_bytes)
            
            passwords[site_name] = encrypted_password
            
            # Enregistre de manière persistante la donné
            save_passwords_to_storage(passwords)
            ###########################################
        elif action.lower() == "q":
           # Demande à l'utilisateur s'il souhaite sauvegarder l'état du programme avant de quitter
           save = input("Voulez-vous sauvegarder l'état du programme avant de quitter ? (o/n) ")
           if save.lower() == "o":
               # Enregistre les mots de passe dans le fichier
               save_passwords_to_storage(passwords)
               print("État du programme enregistré avec succès.")
           # Quitte le programme
           break

            
        elif action.lower() == "l":
            # Demande à l'utilisateur de saisir le nom du site internet dont il souhaite lire le mot de passe
            site_name = input("Entrez le nom du site internet pour lequel vous souhaitez lire le mot de passe : ")

               # Vérifie si le nom du site internet est présent dans le dictionnaire
        if site_name in passwords:
            # Récupère le mot de passe chiffré associé au nom du site internet
            encrypted_password = passwords[site_name]

            # Déchiffre le mot de passe en utilisant l'objet Fernet
            password_bytes = fernet.decrypt(encrypted_password)

            # Décode les bytes en utf-8 et affiche le mot de passe déchiffré
            password = password_bytes.decode("utf-8")
            print(f"Le mot de passe pour le site '{site_name}' est : {password}")
        else:
            print(f"Aucun mot de passe trouvé pour le site '{site_name}'.")
            
else:
        print("Action non valide. Veuillez réessayer.")

         ###########################################################


