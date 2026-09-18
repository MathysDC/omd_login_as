"""Clés publiques Ed25519 du tableau de bord Omydoo, par identifiant (`kid`).

Seule la clé publique vit ici : l'instance ne détient aucun secret. Plusieurs clés peuvent
coexister le temps d'une rotation ; retirer l'ancienne une fois le tableau de bord basculé.
"""

CLES_PUBLIQUES: dict[str, str] = {
    "k1": "6P0NcrrjbtmDL6F1ObuvHugE5791psn9wmruqifX4bo=",
}
