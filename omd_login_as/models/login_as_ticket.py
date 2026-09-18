from datetime import timedelta

from psycopg2 import IntegrityError

from odoo import fields, models


class LoginAsTicket(models.Model):
    """Identifiants (jti) des tickets de connexion déjà consommés : garantit l'usage unique."""

    _name = "login.as.ticket"
    _description = "Ticket de login as consommé"
    _rec_name = "jti"
    _order = "id desc"

    jti = fields.Char(required=True, readonly=True)
    login = fields.Char(readonly=True)
    expire_le = fields.Datetime(required=True, readonly=True)

    def init(self):
        """Poser l'index unique sur ``jti`` : c'est lui qui départage deux consommations concurrentes."""
        self.env.cr.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS login_as_ticket_jti_unique ON login_as_ticket (jti)"
        )

    def consommer(self, jti, expire_le, login):
        """Enregistrer un jti ; rendre ``False`` s'il l'était déjà (rejeu), ``True`` sinon.

        :param str jti: identifiant du ticket
        :param datetime expire_le: expiration du ticket, pour la purge
        :param str login: utilisateur visé, pour la trace
        :rtype: bool
        """
        self._purger()
        try:
            with self.env.cr.savepoint():
                self.sudo().create({"jti": jti, "login": login, "expire_le": expire_le})
        except IntegrityError:
            return False
        return True

    def _purger(self):
        """Supprimer les jti expirés depuis plus d'une heure : ils ne peuvent plus être rejoués."""
        seuil = fields.Datetime.now() - timedelta(hours=1)
        self.sudo().search([("expire_le", "<", seuil)]).unlink()
