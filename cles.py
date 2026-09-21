"""Clés publiques Ed25519 du tableau de bord Omydoo, par identifiant (`kid`).

Seule la clé publique vit ici : l'instance ne détient aucun secret. Plusieurs clés peuvent
coexister le temps d'une rotation ; retirer l'ancienne une fois le tableau de bord basculé.
"""

# ⚠️ Pas d'annotation `dict[str, str]` : elle s'évalue à l'import et Odoo 14 tourne en
# Python 3.7, où le type natif n'est pas indiçable.
CLES_PUBLIQUES = {
    "k1": "6P0NcrrjbtmDL6F1ObuvHugE5791psn9wmruqifX4bo=",
}
