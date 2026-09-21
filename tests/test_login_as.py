import base64
import json
import secrets
import time

from odoo.tests import HttpCase, TransactionCase, tagged
from odoo.tests.common import HOST

from .. import cles, ed25519_pur
from . import signature_de_test
from ..jetons import PREFIXE, JetonRefuse, verifier


def _b64url(octets):
    """Encoder en base64url sans remplissage."""
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")


@tagged("omydoo", "post_install", "-at_install")
class TestLoginAs(HttpCase):
    """Parcours complet du login as avec une paire de clés éphémère."""

    @classmethod
    def setUpClass(cls):
        """Générer une clé Ed25519 de test et la déclarer comme clé publique connue du module.

        ⚠️ La signature passe par la bibliothèque quand elle est là, et par le signeur **de test**
        sinon (image Odoo 14). Le module, lui, ne signe jamais : il ne sait que vérifier."""
        super().setUpClass()
        cls.graine = secrets.token_bytes(32)
        publique = signature_de_test.cle_publique(cls.graine)
        # Pas de `patch.dict` : le cadre de test d'Odoo 18 inspecte les patches et ne le connaît pas.
        cls.cles_avant = dict(cles.CLES_PUBLIQUES)
        cles.CLES_PUBLIQUES.clear()
        cles.CLES_PUBLIQUES["test"] = base64.b64encode(publique).decode("ascii")
        cls.addClassCleanup(cls._restaurer_cles)
        # ⚠️ `HOST` et non `cls.base_url()` : cette méthode n'existe pas sur la classe en Odoo 14,
        # alors que `HOST` est exporté par le cadre de test de toutes les versions.
        cls.hote = HOST
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
        signature = signature_de_test.signer(self.graine, f"{PREFIXE}.{corps}".encode("ascii"))
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


@tagged("omydoo", "post_install", "-at_install")
class TestEd25519Pur(TransactionCase):
    """Le recours en Python pur — éprouvé contre la RFC **et** contre la bibliothèque auditée.

    ⭐⭐ Ce double éprouvage est la condition qui rend acceptable d'avoir écrit cette vérification
    nous-mêmes. Les vecteurs officiels prouvent la conformité ; le différentiel prouve qu'on rend
    exactement le même verdict que `cryptography`, sur des cas valides **et** falsifiés.
    """

    # RFC 8032 §7.1 — (clé publique, message, signature), en hexadécimal.
    VECTEURS = [
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc"
            "61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e45"
            "8f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae"
            "67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ]

    def test_les_vecteurs_officiels_de_la_RFC_8032_passent(self):
        """Conformité : les trois vecteurs §7.1, dont le message vide et un message d'un octet."""
        for publique, message, signature in self.VECTEURS:
            with self.subTest(message=message or "(vide)"):
                self.assertTrue(
                    ed25519_pur.verifier_signature(
                        bytes.fromhex(publique), bytes.fromhex(message), bytes.fromhex(signature)
                    )
                )

    def test_un_seul_bit_change_et_le_vecteur_est_REFUSE(self):
        """⭐ Contrôle négatif des vecteurs : sans lui, une fonction qui rendrait toujours `True`
        passerait le test précédent."""
        publique, message, signature = self.VECTEURS[2]
        octets = bytearray(bytes.fromhex(signature))
        octets[0] ^= 0x01
        self.assertFalse(
            ed25519_pur.verifier_signature(
                bytes.fromhex(publique), bytes.fromhex(message), bytes(octets)
            )
        )

    def test_differentiel_contre_cryptography_valides_ET_falsifies(self):
        """⭐⭐ Même verdict que la bibliothèque auditée, sur 60 signatures valides et 60 altérées.

        ⚠️ Ignoré si `cryptography` est absente (c'est le cas sur l'image Odoo 14, celle qui
        **utilise** ce recours) : le différentiel tourne alors sur les séries 15 à 19, où les deux
        implémentations coexistent. C'est suffisant — le code éprouvé est le même partout.
        """
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            self.skipTest("cryptography absente : différentiel couvert par les autres séries")

        for i in range(60):
            privee = Ed25519PrivateKey.generate()
            publique = privee.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            message = secrets.token_bytes(i % 40)
            signature = privee.sign(message)
            self.assertTrue(ed25519_pur.verifier_signature(publique, message, signature))
            # Le même, un octet changé quelque part dans la signature : les deux doivent refuser.
            altere = bytearray(signature)
            altere[i % 64] ^= 0x80
            self.assertFalse(ed25519_pur.verifier_signature(publique, message, bytes(altere)))

    def test_les_entrees_absurdes_rendent_False_sans_jamais_lever(self):
        """⛔ Longueurs fausses, point hors courbe, `S` non réduit : refus, jamais d'exception.

        Le refus de `S >= L` est le moins évident des trois et le plus important : sans lui, une
        signature reste valide sous une forme **malléable**."""
        publique, message, signature = self.VECTEURS[1]
        pub, msg, sig = bytes.fromhex(publique), bytes.fromhex(message), bytes.fromhex(signature)

        self.assertFalse(ed25519_pur.verifier_signature(b"", msg, sig))
        self.assertFalse(ed25519_pur.verifier_signature(pub, msg, b"court"))
        self.assertFalse(ed25519_pur.verifier_signature(b"\xff" * 32, msg, sig))  # y hors corps
        # `S` remplacé par une valeur supérieure à l'ordre du groupe.
        non_reduit = sig[:32] + (b"\xff" * 32)
        self.assertFalse(ed25519_pur.verifier_signature(pub, msg, non_reduit))
