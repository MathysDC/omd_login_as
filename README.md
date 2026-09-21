# omd_login_as

Module Odoo qui permet au tableau de bord Omydoo d'ouvrir une session Odoo au nom de n'importe
quel utilisateur interne, sans mot de passe et sans secret sur l'instance.

## Fonctionnement

- Le tableau de bord détient une clé privée Ed25519 ; ce module n'embarque que la clé publique
  (`cles.py`).
- `POST /omd/login_as` reçoit un ticket signé (`typ=login`) valable 60 s, lié à l'hôte appelé et à
  la base, à usage unique (table `login.as.ticket`). Il ouvre la session puis redirige vers `/web`.
- `GET /omd/login_as/users` rend les utilisateurs internes actifs sous jeton signé (`typ=users`).
- `GET /omd/login_as/health` rend version et identifiants de clés.

Le ticket voyage dans le corps d'un POST : il n'apparaît ni dans les journaux d'accès ni dans
l'historique du navigateur.

## Disposition et branches

Le `__manifest__.py` est à la **racine du dépôt** : la plateforme Omydoo clone le dépôt tel quel
dans `/mnt/extra-addons/omd_login_as`, le dépôt *est* le module.


Une branche par série Odoo : `15.0`, `16.0`, `17.0`, `18.0`, `19.0`. Le code est identique, seule
la `version` du manifeste change — Odoo refuse un manifeste dont la série ne correspond pas.

Le module s'adapte à **deux contrats de session**, distingués par la signature de
`Session.finalize` et non par un numéro de version : `finalize()` sans argument en 14/15,
`finalize(env)` en 16 et au-delà. De même, `request.make_response` n'accepte `status` qu'à partir
de la 16, donc la réponse est construite sans lui et son `status_code` est posé ensuite.

⛔ **Odoo 14 n'est pas supporté** : son image officielle n'embarque pas `cryptography`, dont
dépend la vérification des signatures Ed25519. Mesuré le 2026-09-21 sur `odoo:14.0`.

## Rotation de clé

Ajouter la nouvelle clé publique dans `CLES_PUBLIQUES` sous un nouveau `kid`, publier, basculer le
tableau de bord sur le nouveau `kid`, puis retirer l'ancienne clé.

## Tests

```
odoo-bin -d <base> -i omd_login_as --test-tags omydoo --stop-after-init
```

Éprouvé dans les **images officielles** (série ↔ image), contre un PostgreSQL 16 :
`15.0`, `16.0`, `17.0-20260630`, `18.0-20260630`, `19.0-20260630` — 7 tests verts sur chacune.
