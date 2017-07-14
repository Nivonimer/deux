from __future__ import absolute_import, unicode_literals

import pyotp
import datetime
from uuid import uuid4
import qrcode


from deux.app_settings import mfa_settings
from deux.constants import CHALLENGE_TYPES, SMS, QRCODE


class TotpAuth(object):
    def __init__(self, secret=None):
        if secret is None:
            secret = pyotp.random_base32()
        self.secret = secret
        self.totp = pyotp.TOTP(secret)

    def generate_token(self):
        return self.totp.now()

    def valid(self, token):
        token = int(token)
        now = datetime.datetime.now()
        time30secsago = now + datetime.timedelta(seconds=-30)
        try:
            valid_now = self.totp.verify(token)
            valid_past = self.totp.verify(token, for_time=time30secsago)
            return valid_now or valid_past
        except Exception:
            return False

    def qrcode(self, username):
        uri = self.totp.provisioning_uri(username)
        return qrcode.make(uri)

    def qrcode_uri(self, username):
        return self.totp.provisioning_uri(username)


def generate_qrcode_url(bin_key, username):
    return TotpAuth(bin_key).qrcode_uri(username)


def generate_mfa_code(bin_key, drift=0):
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


def verify_mfa_code(bin_key, mfa_code, challenge_type=SMS):
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
        mfa_code = int(mfa_code)
    except ValueError:
        return False
    else:
        return TotpAuth(bin_key).valid(mfa_code)


class MultiFactorChallenge(object):
    """
    A class that represents a supported challenge and has the ability to
    execute the challenge.

    :param instance: :class:`MultiFactorAuth` instance to use.
    :param challenge_type: Challenge type being used for this object.
    :raises AssertionError: If ``challenge_type`` is not a supported
        challenge type.
    """

    def __init__(self, instance, challenge_type):
        assert challenge_type in CHALLENGE_TYPES, (
            "Inputted challenge type is not supported."
        )
        self.instance = instance
        self.challenge_type = challenge_type

    def generate_challenge(self):
        """
        Generates and executes the challenge object based on the challenge
        type of this object.
        """
        dispatch = {
            SMS: self._sms_challenge,
            QRCODE: self._qrcode_challenge
        }
        for challenge in CHALLENGE_TYPES:
            assert challenge in dispatch, (
                "'{challenge}' does not have a challenge dispatch "
                "method.".format(challenge=challenge)
            )
        return dispatch[self.challenge_type]()

    def _sms_challenge(self):
        """Executes the SMS challenge."""
        code = generate_mfa_code(bin_key=self.instance.sms_bin_key)
        mfa_settings.SEND_MFA_TEXT_FUNC(
            mfa_instance=self.instance, mfa_code=code)

    def _qrcode_challenge(self):
        """Executes your QRCODE challenge method."""
        return
