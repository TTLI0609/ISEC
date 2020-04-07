from subprocess import Popen, PIPE
import base64

# ce script suppose qu'il a affaire à OpenSSL v1.1.1
# vérifier avec "openssl version" en cas de doute.
# attention à MacOS, qui fournit à la place LibreSSL.

# en cas de problème, cette exception est déclenchée
class OpensslError(Exception):
    pass

# Il vaut mieux être conscient de la différence entre str() et bytes()
# cf /usr/doc/strings.txt


def encrypt(plaintext, passphrase, cipher='aes-128-cbc'):
    """invoke the OpenSSL library (though the openssl executable which must be
       present on your system) to encrypt content using a symmetric cipher.

       The passphrase is an str object (a unicode string)
       The plaintext is str() or bytes()
       The output is bytes()

       # encryption use
       >>> message = "texte avec caractères accentués"
       >>> c = encrypt(message, 'foobar')
       
    """
    # prépare les arguments à envoyer à openssl
    pass_arg = 'pass:{0}'.format(passphrase)
    #args = ['/usr/local/opt/openssl/bin/openssl', 'enc', '-' + cipher, '-base64', '-pass', pass_arg, '-pbkdf2']
    args = ['openssl', 'enc', '-' + cipher, '-base64', '-pass', pass_arg, '-pbkdf2']
    
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(plaintext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return stdout.decode()


def decrypt(ciphertext, passphrase, cipher='aes-128-cbc'):

    # prépare les arguments à envoyer à openssl
    pass_arg = 'pass:{0}'.format(passphrase)
    #args = ['/usr/local/opt/openssl/bin/openssl', 'enc', '-d', '-' + cipher, '-base64', '-pass', pass_arg, '-pbkdf2']
    args = ['openssl', 'enc', '-d', '-' + cipher, '-base64', '-pass', pass_arg, '-pbkdf2']
    
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode('utf-8')
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(ciphertext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return stdout.decode()

#  return (base64.base64encrypt(stdout)).decode()



def encrypt2(plaintext, fichier):


    # prépare les arguments à envoyer à openssl
    #fichier = '/Users/rymchaouche/Documents/Master/nasa/public_key'
    #message = "Réprimer la fraude et l’évasion fiscales: la Commission indique la voie à suivre"
    args = ['openssl', 'pkeyutl', '-encrypt', '-pubin', '-inkey', fichier]
    
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(plaintext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return base64.b64encode(stdout).decode()

def decrypt2(plaintext, key):


    # prépare les arguments à envoyer à openssl
    #fichier = '/Users/rymchaouche/Documents/Master/nasa/public_key'
    #message = "Réprimer la fraude et l’évasion fiscales: la Commission indique la voie à suivre"
    args = ['openssl', 'pkeyutl', '-decrypt', '-inkey', key]
    
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(plaintext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return stdout.decode()

def signature(plaintext, fic_Priv_key):


    args = ['openssl', 'dgst', '-sha256', '-sign', fic_Priv_key]
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(plaintext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return base64.b64encode(stdout).decode()


def sign_profil(a_signer, signeur, connexion, private_key = 'key_private_perso.pem'):
    # a_signer : le nom de celui que vous allez signer
    # signeur : votre nom
    # private_key : le fichier contenant votre clef privé
    # connexion : le c = Connexion() a faire pour utiliser uglix
    
    dico = {}
    dico["signer"] = signeur;
    pk_a_signer = connexion.get("/bin/key-management/"+a_signer+"/pk")
    args = ['openssl', 'dgst', '-sha256', '-sign', private_key]

    if isinstance(pk_a_signer, str):
        plaintext = pk_a_signer.encode()

    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = pipeline.communicate(plaintext)

    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)
    dico["signature"] = base64.b64encode(stdout).decode()+"\n"
    print(connexion.post('/bin/sendmail', to = a_signer, subject = "signature", content = dico))
    return 

#print(c.post('/bin/key-management/upload-signature', signer='debrasmith', signature= 'nstMmoQfZdARP8S/WLSC3wTUTldxN7qcAFIVtuk7tfnlSvGBzp0uldaYcqPn9DO18RZTbjwa5Ovbbh3M6XqGsTifnY6q+uh9FVAIVv8uciNQbRTnZjNsN5vT9ipjh3o6yrLspCt7YfzKXcDWQPwQt6ZuhLayRM7us7kxA0Y+aerEjVE693tNVOJ23Uzj17JhARTraVzbizpDz+S/O+lUjTgLV4R17yAK2Hs4s2vXcZ1iRTYWOODTjkObzKl6N2sjN7fmx93xJN7zyZ/farU8bthxbuafo9PD//fE/GJ1PItTmKVvmihvOQvX+04UxJT7NG856zOyU+V8aevBJvdtEA==\n'))


# openssl.sign_profil("ubecker", "raymondstephens", c, private_key = "./MyLargePrivK")


# print(c.get('/bin/key-management/raymondstephens'))
