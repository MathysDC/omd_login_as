"""Vérification des jetons signés du login as — Python pur, sans dépendance à Odoo.

Format : ``omd1.<payload base64url>.<signature base64url>``, signature Ed25519 des octets
``"omd1.<payload base64url>"``. La vérification passe par ``cryptography`` quand l'image l'embarque
(séries 15 à 19), et par ``ed25519_pur`` sinon (série 14) — cf. ce module pour le pourquoi. Le payload est un JSON portant ``kid``, ``typ``, ``jti``, ``iat``,
``exp``, ``aud``, ``db`` et, pour un ticket de connexion, ``uid`` et ``login``.
"""
import base64
import json
import time

try:  # chemin nominal : la bibliothèque auditée, présente sur les images 15 à 19
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    _BIBLIOTHEQUE = True
except ImportError:  # recours : l'image Odoo 14 n'embarque AUCUNE cryptographie asymétrique
    from .ed25519_pur import verifier_signature

    _BIBLIOTHEQUE = False

PREFIXE = "omd1"
DUREE_MAX_S = 300
TOLERANCE_HORLOGE_S = 30
LONGUEUR_JTI = (16, 64)


class JetonRefuse(Exception):
    """Jeton rejeté ; ``raison`` est un mot-clé stable, jamais un détail exploitable."""

    def __init__(self, raison: str):
        self.raison = raison
        super().__init__(raison)


def _decoder_b64url(valeur: str) -> bytes:
    """Décoder du base64url sans remplissage."""
    return base64.urlsafe_b64decode(valeur + "=" * (-len(valeur) % 4))


def _verifier_signature(cle_b64, message, signature):
    """Vérifie la signature avec la bibliothèque si elle est là, sinon avec le recours pur.

    ⭐ Le choix est fait **une fois, à l'import**, pas à chaque appel : une image donnée a la
    bibliothèque ou ne l'a pas, et cela ne change pas en cours de vie du processus.

    ⛔ Toute anomalie (clé mal encodée, longueur fausse) rend `False`, jamais une exception : la
    seule issue d'une signature qu'on ne peut pas valider est le refus.
    """
    try:
        cle = base64.b64decode(cle_b64)
    except (ValueError, TypeError):
        return False
    if _BIBLIOTHEQUE:
        try:
            Ed25519PublicKey.from_public_bytes(cle).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True
    return verifier_signature(cle, message, signature)


def verifier(jeton, *, cles_publiques, typ, aud, db, maintenant=None) -> dict:
    """Vérifier un jeton et rendre son payload, ou lever ``JetonRefuse``.

    La signature est contrôlée avant toute lecture des revendications : seul ``kid`` est lu
    avant, pour choisir la clé. L'usage unique du ``jti`` n'est pas traité ici (il demande un
    état), c'est le rôle du modèle ``login.as.ticket``.

    :param str jeton: le jeton tel que reçu
    :param dict cles_publiques: clés publiques Ed25519 (32 octets en base64) par ``kid``
    :param str typ: type attendu, ``login`` ou ``users``
    :param str aud: hôte réellement appelé (sans port)
    :param str db: nom de la base courante
    :param float maintenant: horloge injectable pour les tests
    :return: le payload vérifié
    :rtype: dict
    :raises JetonRefuse: pour toute anomalie
    """
    if not isinstance(jeton, str):
        raise JetonRefuse("format")
    parties = jeton.split(".")
    if len(parties) != 3 or parties[0] != PREFIXE:
        raise JetonRefuse("format")
    payload_b64, signature_b64 = parties[1], parties[2]
    try:
        payload = json.loads(_decoder_b64url(payload_b64))
        signature = _decoder_b64url(signature_b64)
    except (ValueError, UnicodeDecodeError):
        raise JetonRefuse("format") from None
    if not isinstance(payload, dict):
        raise JetonRefuse("format")

    kid = payload.get("kid")
    cle_b64 = cles_publiques.get(kid) if isinstance(kid, str) else None
    if not cle_b64:
        raise JetonRefuse("cle_inconnue")
    signe = "{}.{}".format(PREFIXE, payload_b64).encode("ascii")
    if not _verifier_signature(cle_b64, signe, signature):
        raise JetonRefuse("signature")

    if payload.get("typ") != typ:
        raise JetonRefuse("type")
    iat, exp = payload.get("iat"), payload.get("exp")
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)) or isinstance(iat, bool) or isinstance(exp, bool):
        raise JetonRefuse("horodatage")
    instant = time.time() if maintenant is None else maintenant
    if iat > instant + TOLERANCE_HORLOGE_S:
        raise JetonRefuse("futur")
    if exp < instant:
        raise JetonRefuse("expire")
    if exp - iat > DUREE_MAX_S:
        raise JetonRefuse("duree")
    if not isinstance(aud, str) or payload.get("aud") != aud.lower():
        raise JetonRefuse("audience")
    if payload.get("db") != db:
        raise JetonRefuse("base")
    jti = payload.get("jti")
    if not isinstance(jti, str) or not (LONGUEUR_JTI[0] <= len(jti) <= LONGUEUR_JTI[1]):
        raise JetonRefuse("jti")
    if typ == "login":
        uid, login = payload.get("uid"), payload.get("login")
        # uid 1 est le superutilisateur technique : jamais une cible de connexion.
        if not isinstance(uid, int) or isinstance(uid, bool) or uid < 2 or not isinstance(login, str) or not login:
            raise JetonRefuse("utilisateur")
    return payload
