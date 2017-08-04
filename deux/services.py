from __future__ import absolute_import, unicode_literals

import pyotp
import datetime
from uuid import uuid4
import qrcode
import urllib

from deux.app_settings import mfa_settings
from deux.constants import CHALLENGE_TYPES, SMS, QRCODE
from deux.gateways import send_sms


class TotpAuth(object):
    def __init__(self, secret=None):
        if secret is None:
            secret = pyotp.random_base32()
        self.secret = secret
        self.totp = pyotp.TOTP(secret, 
            digits=mfa_settings.MFA_CODE_NUM_DIGITS, 
            interval=mfa_settings.MFA_CODE_INTERVAL)

    def generate_token(self):
        return self.totp.now()

    def valid(self, token):
        now = datetime.datetime.now()
        interval = now + datetime.timedelta(seconds=-mfa_settings.MFA_CODE_INTERVAL)
        try:
            valid_now = self.totp.verify(token)
            valid_past = self.totp.verify(token, for_time=interval)

            return valid_now or valid_past
        except Exception:
            return False

    def qrcode(self, username):
        uri = self.totp.provisioning_uri(username)
        return qrcode.make(uri)

    def qrcode_uri(self, username, issuer_name):
        return self.totp.provisioning_uri(username, issuer_name=issuer_name)


def generate_qrcode_url(bin_key, username, issuer_name):
    url = TotpAuth(bin_key).qrcode_uri(username, issuer_name)
    return urllib.quote(url)


def generate_mfa_code(bin_key):
    """
    Generates an MFA code based on the ``bin_key`` for the current timestamp
    offset by the ``drift``.

    :param bin_key: The secret key to be converted into an MFA code
    :param drift: Number of time steps to shift the conversion.
    """
    return TotpAuth(bin_key).generate_token()


def generate_key():
    """Generates a key used for secret keys."""
    return uuid4().hex


def verify_mfa_code(bin_key, mfa_code):
    """
    Verifies that the inputted ``mfa_code`` is a valid code for the given
    secret key. We check the ``mfa_code`` against the current time stamp as
    well as one time step before and after.

    :param bin_key: The secret key to verify the MFA code again.
    :param mfa_code: The code whose validity this function tests.
    """
    if not mfa_code:
        return False
    try:
        mfa_code = str(mfa_code)
    except ValueError:
        return False
    else:
        return TotpAuth(bin_key).valid(mfa_code)
