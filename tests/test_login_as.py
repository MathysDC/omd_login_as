import base64
import json
import secrets
import time
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from odoo.tests import HttpCase, tagged

from .. import cles
from ..jetons import PREFIXE, JetonRefuse, verifier


def _b64url(octets):
    """Encoder en base64url sans remplissage."""
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")


@tagged("omydoo", "post_install", "-at_install")
class TestLoginAs(HttpCase):
    """Parcours complet du login as avec une paire de clés éphémère."""

    @classmethod
    def setUpClass(cls):
        """Générer une clé Ed25519 de test et la déclarer comme clé publique connue du module."""
        super().setUpClass()
        cls.cle_privee = Ed25519PrivateKey.generate()
        publique = cls.cle_privee.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        # Pas de `patch.dict` : le cadre de test d'Odoo 18 inspecte les patches et ne le connaît pas.
        cls.cles_avant = dict(cles.CLES_PUBLIQUES)
        cles.CLES_PUBLIQUES.clear()
        cles.CLES_PUBLIQUES["test"] = base64.b64encode(publique).decode("ascii")
        cls.addClassCleanup(cls._restaurer_cles)
        cls.hote = urlparse(cls.base_url()).hostname
        cls.admin = cls.env.ref("base.user_admin")

    @classmethod
    def _restaurer_cles(cls):
        """Remettre les clés publiques réelles du module après la classe de tests."""
        cles.CLES_PUBLIQUES.clear()
        cles.CLES_PUBLIQUES.update(cls.cles_avant)

    def _jeton(self, typ, **surcharges):
        """Signer un jeton valide par défaut, en laissant chaque test altérer une revendication."""
        maintenant = int(time.time())
        payload = {
            "kid": "test", "typ": typ, "jti": secrets.token_urlsafe(24), "iat": maintenant, "exp": maintenant + 60,
            "aud": self.hote, "db": self.env.cr.dbname,
        }
        if typ == "login":
            payload.update({"uid": self.admin.id, "login": self.admin.login})
        payload.update(surcharges)
        corps = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signature = self.cle_privee.sign(f"{PREFIXE}.{corps}".encode("ascii"))
        return f"{PREFIXE}.{corps}.{_b64url(signature)}"

    def _connecter(self, ticket):
        """Poster un ticket comme le ferait le formulaire ouvert par le tableau de bord."""
        return self.url_open("/omd/login_as", data={"ticket": ticket}, allow_redirects=False)

    def test_sante(self):
        """La sonde répond et annonce la clé de test."""
        reponse = self.url_open("/omd/login_as/health")
        self.assertEqual(reponse.status_code, 200)
        self.assertEqual(reponse.json()["kids"], ["test"])

    def test_liste_utilisateurs(self):
        """Un jeton ``users`` valide rend les utilisateurs internes, l'admin marqué comme tel."""
        reponse = self.url_open("/omd/login_as/users", headers={"Authorization": f"Bearer {self._jeton('users')}"})
        self.assertEqual(reponse.status_code, 200)
        par_id = {u["id"]: u for u in reponse.json()["users"]}
        self.assertIn(self.admin.id, par_id)
        self.assertTrue(par_id[self.admin.id]["is_admin"])
        self.assertNotIn(1, par_id)

    def test_liste_refusee_sans_jeton_ou_mauvais_type(self):
        """Sans jeton, ou avec un ticket de connexion à la place, la liste est refusée."""
        self.assertEqual(self.url_open("/omd/login_as/users").status_code, 403)
        reponse = self.url_open("/omd/login_as/users", headers={"Authorization": f"Bearer {self._jeton('login')}"})
        self.assertEqual(reponse.status_code, 403)

    def test_connexion_et_rejeu(self):
        """Un ticket valide ouvre la session (redirection, cookie) ; le même ticket est ensuite refusé."""
        ticket = self._jeton("login")
        reponse = self._connecter(ticket)
        self.assertIn(reponse.status_code, (302, 303))
        self.assertIn("session_id", reponse.cookies)
        session = self.url_open("/web/session/get_session_info", data=json.dumps({"jsonrpc": "2.0", "method": "call", "params": {}}), headers={"Content-Type": "application/json"})
        self.assertEqual(session.json()["result"]["uid"], self.admin.id)
        self.assertEqual(self._connecter(ticket).status_code, 403)

    def test_refus(self):
        """Audience, base, expiration, signature altérée, clé inconnue, login discordant : tous refusés."""
        cas = {
            "audience": self._jeton("login", aud="autre.exemple.fr"),
            "base": self._jeton("login", db="autre_base"),
            "expire": self._jeton("login", iat=int(time.time()) - 120, exp=int(time.time()) - 60),
            "cle": self._jeton("login", kid="inconnue"),
            "login": self._jeton("login", login="pas-le-bon"),
            "superutilisateur": self._jeton("login", uid=1, login="__system__"),
            "altere": self._jeton("login")[:-4] + "AAAA",
        }
        for nom, ticket in cas.items():
            with self.subTest(nom):
                self.assertEqual(self._connecter(ticket).status_code, 403)

    def test_ticket_en_url_refuse(self):
        """Le même ticket, valide, est refusé s'il arrive par la query string et non par le corps."""
        ticket = self._jeton("login")
        reponse = self.url_open(f"/omd/login_as?ticket={ticket}", data={"autre": "1"}, allow_redirects=False)
        self.assertEqual(reponse.status_code, 403)
        self.assertIn(self._connecter(ticket).status_code, (302, 303))

    def test_verifier_pur(self):
        """La fonction pure rejette une durée de vie excessive et un jeton mal formé."""
        with self.assertRaises(JetonRefuse) as refus:
            verifier(self._jeton("login", exp=int(time.time()) + 3600), cles_publiques=cles.CLES_PUBLIQUES, typ="login", aud=self.hote, db=self.env.cr.dbname)
        self.assertEqual(refus.exception.raison, "duree")
        with self.assertRaises(JetonRefuse):
            verifier("pas.un.jeton", cles_publiques=cles.CLES_PUBLIQUES, typ="login", aud=self.hote, db=self.env.cr.dbname)
