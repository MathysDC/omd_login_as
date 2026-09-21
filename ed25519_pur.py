"""Vérification Ed25519 **en Python pur** — le recours des images sans `cryptography`.

⭐⭐ Pourquoi ce fichier existe : l'image officielle `odoo:14.0` n'embarque **aucune** bibliothèque
de cryptographie asymétrique (mesuré le 2026-09-21 : ni `cryptography`, ni `nacl`, ni `pyOpenSSL`,
ni `Crypto`), et tourne en Python 3.7. Sans ce recours, le login as était impossible sur cette
série. Les séries 15 à 19, elles, ont `cryptography` et **continuent de l'utiliser** : ce code
n'est qu'un filet, jamais le chemin nominal.

⛔ **Écrire de la cryptographie soi-même est une décision, pas une facilité.** Ce qui la rend
acceptable ici, et seulement ici :

1. **Vérification uniquement.** Aucune clé privée, aucune signature produite, aucun aléa à tirer —
   les trois endroits où une implémentation maison se trompe le plus gravement.
2. **Algorithme de référence.** C'est l'implémentation de la RFC 8032 §6, transcrite sans
   optimisation. Rien n'est inventé.
3. **Éprouvée deux fois** : contre les **vecteurs officiels** de la RFC 8032 §7.1, et en
   **différentiel** contre `cryptography` sur des milliers de cas, valides comme falsifiés.

⚠️ Les trois refus qui comptent, et qu'une implémentation naïve oublie : un `S` supérieur ou égal à
l'ordre du groupe (malléabilité), un point non décodable, et une coordonnée `y` hors du corps. Les
trois rendent `False`, jamais une exception.
"""

import hashlib

# Corps premier et paramètres de la courbe edwards25519 (RFC 8032 §5.1).
_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_L = 2**252 + 27742317777372353535851937790883648493  # ordre du sous-groupe premier
_RACINE_MOINS_UN = pow(2, (_P - 1) // 4, _P)


def _sha512(donnees):
    """Condensé SHA-512, seul primitif emprunté (bibliothèque standard, partout)."""
    return hashlib.sha512(donnees).digest()


def _ajouter(point_a, point_b):
    """Addition de deux points en coordonnées étendues (X, Y, Z, T) — RFC 8032 §6."""
    a = (point_a[1] - point_a[0]) * (point_b[1] - point_b[0]) % _P
    b = (point_a[1] + point_a[0]) * (point_b[1] + point_b[0]) % _P
    c = 2 * point_a[3] * point_b[3] * _D % _P
    e = 2 * point_a[2] * point_b[2] % _P
    f, g, h, i = b - a, e - c, e + c, b + a
    return (f * g, h * i, g * h, f * i)


def _multiplier(scalaire, point):
    """Multiplication scalaire par doublements successifs (temps non constant — sans objet ici :
    scalaire et point sont **publics**, il n'y a aucun secret à protéger d'une attaque temporelle)."""
    resultat = (0, 1, 1, 0)  # élément neutre
    while scalaire > 0:
        if scalaire & 1:
            resultat = _ajouter(resultat, point)
        point = _ajouter(point, point)
        scalaire >>= 1
    return resultat


def _egaux(point_a, point_b):
    """Égalité projective : on compare les produits croisés, jamais les coordonnées brutes."""
    if (point_a[0] * point_b[2] - point_b[0] * point_a[2]) % _P != 0:
        return False
    return (point_a[1] * point_b[2] - point_b[1] * point_a[2]) % _P == 0


def _retrouver_x(y, signe):
    """Retrouve `x` à partir de `y` et du bit de signe. Rend `None` si le point n'est pas sur la
    courbe — refus explicite, jamais une valeur inventée."""
    if y >= _P:
        return None
    carre = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if carre == 0:
        return None if signe else 0
    x = pow(carre, (_P + 3) // 8, _P)
    if (x * x - carre) % _P != 0:
        x = x * _RACINE_MOINS_UN % _P
    if (x * x - carre) % _P != 0:
        return None
    if (x & 1) != signe:
        x = _P - x
    return x


def _decompresser(octets):
    """Décode un point compressé (32 octets). `None` si le point n'est pas valide."""
    if len(octets) != 32:
        return None
    y = int.from_bytes(octets, "little")
    signe = y >> 255
    y &= (1 << 255) - 1
    x = _retrouver_x(y, signe)
    return None if x is None else (x, y, 1, x * y % _P)


_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE_X = _retrouver_x(_BASE_Y, 0)
_BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def verifier_signature(cle_publique, message, signature):
    """Vrai si `signature` est une signature Ed25519 valide de `message` par `cle_publique`.

    Ne lève **jamais** : toute entrée mal formée rend `False`. C'est ce qui permet à l'appelant de
    traiter « signature invalide » et « entrée absurde » de la même façon, sans branche oubliée.

    :param bytes cle_publique: clé publique brute, 32 octets
    :param bytes message: message signé
    :param bytes signature: signature, 64 octets
    :rtype: bool
    """
    if len(cle_publique) != 32 or len(signature) != 64:
        return False
    point_cle = _decompresser(cle_publique)
    if point_cle is None:
        return False
    r_octets = signature[:32]
    point_r = _decompresser(r_octets)
    if point_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    # ⛔ Refus de malléabilité : `s` DOIT être réduit modulo l'ordre du groupe.
    if s >= _L:
        return False
    h = int.from_bytes(_sha512(r_octets + cle_publique + message), "little") % _L
    return _egaux(_multiplier(s, _BASE), _ajouter(point_r, _multiplier(h, point_cle)))
