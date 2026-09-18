"""Routes du login as Omydoo.

- ``GET  /omd/login_as/health`` : présence et version du module, identifiants de clés connus.
- ``GET  /omd/login_as/users``  : utilisateurs internes actifs, sous jeton signé ``users``.
- ``POST /omd/login_as``        : ouvre la session de l'utilisateur désigné par un ticket signé
  ``login``, à usage unique, puis redirige vers l'interface.

Le ticket voyage dans le corps d'un POST, jamais dans l'URL : il n'apparaît ni dans les journaux
d'accès ni dans l'historique du navigateur.
"""
import html
import json
import logging
from datetime import datetime, timezone

from odoo import SUPERUSER_ID, http
from odoo.http import request

from .. import cles
from ..jetons import JetonRefuse, verifier

_logger = logging.getLogger(__name__)

VERSION_MODULE = "1.0.0"


def _reponse_json(donnees, statut=200):
    """Rendre une réponse JSON non mise en cache."""
    return request.make_response(
        json.dumps(donnees),
        status=statut,
        headers=[("Content-Type", "application/json; charset=utf-8"), ("Cache-Control", "no-store")],
    )


def _page_refus(titre, statut=403):
    """Rendre la page d'erreur affichée à l'humain, volontairement sans détail technique."""
    titre = html.escape(titre)
    page = (
        "<!doctype html><html lang='fr'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{titre}</title>"
        "<style>body{font-family:system-ui,sans-serif;background:#0b1020;color:#e5e7eb;display:flex;"
        "min-height:100vh;align-items:center;justify-content:center;margin:0}"
        ".card{max-width:420px;padding:2rem;text-align:center;background:#111827;"
        "border:1px solid #1f2937;border-radius:16px}h1{font-size:1.1rem;margin:0 0 .5rem}"
        "p{color:#9ca3af;font-size:.9rem;line-height:1.5;margin:0}</style></head><body>"
        f"<div class='card'><h1>{titre}</h1>"
        "<p>Relancez la connexion depuis le tableau de bord Omydoo.</p></div></body></html>"
    )
    return request.make_response(
        page, status=statut, headers=[("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")]
    )


def _hote_appele():
    """Rendre l'hôte réellement appelé, en minuscules et sans port : c'est l'audience du jeton."""
    return (request.httprequest.host or "").split(":")[0].lower()


def _verifier(jeton, typ):
    """Vérifier un jeton contre les clés connues, l'hôte appelé et la base courante."""
    return verifier(
        jeton, cles_publiques=cles.CLES_PUBLIQUES, typ=typ, aud=_hote_appele(), db=request.env.cr.dbname
    )


def _est_administrateur(utilisateur):
    """Dire si l'utilisateur porte le groupe Administration / Paramètres, quelle que soit la version."""
    groupe = request.env.ref("base.group_system", raise_if_not_found=False)
    if not groupe:
        return False
    # v19 : `all_group_ids` (groupes directs + impliqués) ; v17/v18 : `groups_id`.
    champ = "all_group_ids" if "all_group_ids" in utilisateur._fields else "groups_id"
    return groupe in utilisateur[champ]


def _ouvrir_session(utilisateur):
    """Authentifier la session courante pour cet utilisateur, sans mot de passe.

    Reproduit la fin de ``Session.authenticate`` : pré-session (``pre_login``, ``pre_uid``) puis
    ``finalize``, qui pose base, login, uid, contexte et jeton de session, et fait tourner
    l'identifiant de session. Les clés sont posées par accès mapping : c'est la forme commune aux
    versions 17 à 19. À défaut de ``finalize`` (versions plus anciennes), les attributs sont posés
    directement.
    """
    session = request.session
    if hasattr(session, "finalize"):
        session["pre_login"] = utilisateur.login
        session["pre_uid"] = utilisateur.id
        session.finalize(request.env)
    else:
        session.uid = utilisateur.id
        session.login = utilisateur.login
        session.session_token = utilisateur._compute_session_token(session.sid)
        session.context = dict(request.env(user=utilisateur.id)["res.users"].context_get() or {})
        session.is_dirty = True
    request.update_env(user=utilisateur.id)


class LoginAs(http.Controller):
    """Points d'entrée HTTP du login as."""

    @http.route(
        "/omd/login_as/health", type="http", auth="public", methods=["GET"], csrf=False, sitemap=False, save_session=False
    )
    def sante(self, **kw):
        """Rendre présence, version du module et identifiants de clés, sans ouvrir de session."""
        return _reponse_json({"ok": True, "module": VERSION_MODULE, "kids": sorted(cles.CLES_PUBLIQUES)})

    @http.route(
        "/omd/login_as/users", type="http", auth="public", methods=["GET"], csrf=False, sitemap=False, save_session=False
    )
    def utilisateurs(self, **kw):
        """Lister les utilisateurs internes actifs pour le sélecteur du tableau de bord."""
        autorisation = request.httprequest.headers.get("Authorization", "")
        jeton = autorisation[7:].strip() if autorisation.lower().startswith("bearer ") else ""
        try:
            _verifier(jeton, "users")
        except JetonRefuse as refus:
            _logger.info("omd_login_as: liste refusée (%s) depuis %s", refus.raison, request.httprequest.remote_addr)
            return _reponse_json({"error": refus.raison}, 403)
        utilisateurs = (
            request.env["res.users"]
            .sudo()
            .search([("active", "=", True), ("share", "=", False), ("id", "!=", SUPERUSER_ID)], order="id")
        )
        return _reponse_json(
            {
                "users": [
                    {"id": u.id, "login": u.login, "name": u.name or u.login, "is_admin": _est_administrateur(u)}
                    for u in utilisateurs
                ]
            }
        )

    @http.route("/omd/login_as", type="http", auth="public", methods=["POST"], csrf=False, sitemap=False)
    def connecter(self, **kw):
        """Consommer un ticket de connexion et ouvrir la session de l'utilisateur visé.

        Le ticket est lu dans le corps du formulaire seulement : un ticket passé en query string
        est refusé, sinon il finirait dans les journaux d'accès et l'historique du navigateur.
        """
        if "ticket" in request.httprequest.args:
            _logger.info("omd_login_as: connexion refusée (ticket en URL) depuis %s", request.httprequest.remote_addr)
            return _page_refus("Lien de connexion invalide ou expiré")
        ticket = request.httprequest.form.get("ticket")
        try:
            payload = _verifier(ticket, "login")
        except JetonRefuse as refus:
            _logger.info("omd_login_as: connexion refusée (%s) depuis %s", refus.raison, request.httprequest.remote_addr)
            return _page_refus("Lien de connexion invalide ou expiré")

        utilisateur = request.env["res.users"].sudo().browse(payload["uid"]).exists()
        if (
            not utilisateur
            or utilisateur.id == SUPERUSER_ID
            or not utilisateur.active
            or utilisateur.share
            or utilisateur.login != payload["login"]
        ):
            _logger.info("omd_login_as: connexion refusée (utilisateur) uid=%s", payload["uid"])
            return _page_refus("Utilisateur introuvable")

        expire_le = datetime.fromtimestamp(payload["exp"], tz=timezone.utc).replace(tzinfo=None)
        if not request.env["login.as.ticket"].sudo().consommer(payload["jti"], expire_le, utilisateur.login):
            _logger.warning("omd_login_as: rejeu refusé jti=%s", payload["jti"][:8])
            return _page_refus("Lien de connexion déjà utilisé")

        _ouvrir_session(utilisateur)
        _logger.info("omd_login_as: session ouverte pour %s (jti %s)", utilisateur.login, payload["jti"][:8])
        return request.redirect("/web")
