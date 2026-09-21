"""Signature Ed25519 **pour les tests seulement** — jamais importée à l'exécution.

⭐⭐ Pourquoi elle existe : les tests d'intégration doivent **fabriquer** des jetons valides, donc
signer. Sur l'image Odoo 14, `cryptography` est absente — et c'est précisément la série qu'il faut
éprouver, puisque c'est la seule qui utilise le recours en Python pur, et celle dont l'API de
session diverge le plus.

⛔ **Ce fichier ne fait pas partie du chemin d'exécution.** Le module livré ne sait que *vérifier* ;
signer reste le privilège du tableau de bord, avec sa clé privée. Le garder ici, dans `tests/`, est
ce qui maintient cette frontière lisible : une signature écrite à la main qui fuirait vers le
runtime serait un défaut, pas une commodité.

⚠️ Utilisé **seulement** quand `cryptography` manque : ailleurs, les tests signent avec la
bibliothèque auditée, ce qui fait d'eux un différentiel de plus.
"""

import hashlib

from ..ed25519_pur import _BASE, _L, _P, _ajouter, _multiplier


def _condenser(donnees):
    """Condensé SHA-512."""
    return hashlib.sha512(donnees).digest()


def _comprimer(point):
    """Compresse un point en 32 octets (y sur 255 bits + bit de signe de x) — RFC 8032 §5.1.2."""
    inverse_z = pow(point[2], _P - 2, _P)
    x, y = point[0] * inverse_z % _P, point[1] * inverse_z % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _etendre(graine):
    """Dérive (scalaire, préfixe) d'une graine de 32 octets — RFC 8032 §5.1.5."""
    condense = _condenser(graine)
    scalaire = int.from_bytes(condense[:32], "little")
    scalaire &= (1 << 254) - 8  # efface les 3 bits bas, force le bit 254
    scalaire |= 1 << 254
    return scalaire, condense[32:]


def cle_publique(graine):
    """Clé publique (32 octets) correspondant à une graine privée de 32 octets."""
    scalaire, _ = _etendre(graine)
    return _comprimer(_multiplier(scalaire, _BASE))


def signer(graine, message):
    """Signature Ed25519 (64 octets) du `message` par la graine privée — RFC 8032 §5.1.6."""
    scalaire, prefixe = _etendre(graine)
    publique = _comprimer(_multiplier(scalaire, _BASE))
    r = int.from_bytes(_condenser(prefixe + message), "little") % _L
    point_r = _comprimer(_multiplier(r, _BASE))
    h = int.from_bytes(_condenser(point_r + publique + message), "little") % _L
    return point_r + int.to_bytes((r + h * scalaire) % _L, 32, "little")


# Réexporté pour que le test n'ait pas à connaître les entrailles de la courbe.
__all__ = ["cle_publique", "signer", "_ajouter"]
