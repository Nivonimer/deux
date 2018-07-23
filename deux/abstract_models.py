from __future__ import absolute_import, unicode_literals

import pyotp
import uuid
import re

from django.conf import settings
from django.db import models
from django.utils.crypto import constant_time_compare
from django.utils.translation import ugettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField

from deux.app_settings import mfa_settings
from deux.constants import CHALLENGE_TYPES, DISABLED, SMS, QRCODE
from deux.services import generate_key, generate_mfa_code, verify_mfa_code
from deux.gateways import send_sms, make_call

phone_mask = re.compile('(?<=.{3})[0-9](?=.{2})')


class BackupPhoneManager(models.Manager):
    """
    The :class:`~django.db.models.Manager` object installed as
    ``Device.objects``.
    """
    def backup_phones_for_user(self, user, confirmed=None):
        """
        Returns a queryset for all devices of this class that belong to the
        given user.
        :param user: The user.
        :type user: :class:`~django.contrib.auth.models.User`
        :param confirmed: If ``None``, all matching devices are returned.
            Otherwise, this can be any true or false value to limit the query
            to confirmed or unconfirmed devices, respectively.
        """
        backup_phones = self.model.objects.filter(user=user)
        if confirmed is not None:
            backup_phones = backup_phones.filter(confirmed=bool(confirmed))

        return backup_phones


class AbstractBackupPhone(models.Model):
    """
    Model with phone number and token seed linked to a user.
    """
    PHONE_METHODS = (
        ('voice', _('Phone Call')),
        ('sms', _('Text Message')),
    )

    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )

    phone_number = PhoneNumberField()

    secret_key = models.CharField(
        max_length=32, default=pyotp.random_base32,
        help_text="Hex-Encoded Secret Key"
    )

    method = models.CharField(
        max_length=4,
        default='sms',
        choices=PHONE_METHODS,
        verbose_name=_('method')
    )

    confirmed = models.BooleanField(
        default=False, help_text="Is this device ready for use?"
    )

    objects = BackupPhoneManager()

    @property
    def bin_key(self):
        return self.secret_key

    def generate_challenge(self):
        code = generate_mfa_code(bin_key=self.bin_key)

        if self.method == 'sms':
            send_sms(self.phone_number, code)
        elif self.method == 'voice':
            make_call(self.phone_number, code)

    def verify_challenge_code(self, mfa_code):
        return verify_mfa_code(self.bin_key, mfa_code)

    def get_phone_number(self):
        """Returns the users masked phone number."""
        if mfa_settings.MASKED_PHONE_NUMBER:
            return phone_mask.sub('*', self.phone_number.as_e164)

        return self.phone_number.as_e164

    class Meta:
        abstract = True


class AbstractMultiFactorAuth(models.Model):
    """
    class::AbstractMultiFactorAuth()

    This abstract class holds user information, MFA status, and secret
    keys for the user.
    """

    #: Different status options for this MFA object.
    CHALLENGE_CHOICES = (
        (SMS, "SMS"),
        (QRCODE, "QRCODE"),
        (DISABLED, "Off"),
    )

    #: User this MFA object represents.
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="multi_factor_auth", primary_key=True
    )

    #: User's phone number.
    phone_number = PhoneNumberField(default="", blank=True)

    #: Challenge type used for MFA.
    challenge_type = models.CharField(
        max_length=16, default=DISABLED,
        blank=True, choices=CHALLENGE_CHOICES
    )

    #: Secret key used for backup code.
    backup_key = models.CharField(
        max_length=32, default="", blank=True,
        help_text="Hex-Encoded Secret Key"
    )

    #: Secret key used for codes.
    secret_key = models.CharField(
        max_length=32, default=pyotp.random_base32,
        help_text="Hex-Encoded Secret Key"
    )

    @property
    def enabled(self):
        """Returns if MFA is enabled."""
        return self.challenge_type in CHALLENGE_TYPES

    @property
    def backup_code(self):
        """Returns the users backup code."""
        return self.backup_key.upper()[:mfa_settings.BACKUP_CODE_DIGITS]

    def get_phone_number(self):
        """Returns the users masked phone number."""
        if mfa_settings.MASKED_PHONE_NUMBER:
            return phone_mask.sub('*', self.phone_number.as_e164)

        return self.phone_number.as_e164

    def get_bin_key(self, challenge_type):
        """
        Returns the key associated with the inputted challenge type.

        :param challenge_type: The challenge type the key is requested for.
                               The type must be in the supported
                               `CHALLENGE_TYPES`.
        :raises AssertionError: If ``challenge_type`` is not a supported
                                challenge type.
        """
        assert challenge_type in CHALLENGE_TYPES, (
            "'{challenge}' is not a valid challenge type.".format(
                challenge=challenge_type)
        )
        return {
            SMS: self.secret_key,
            QRCODE: self.secret_key
        }.get(challenge_type, None)

    def enable(self, challenge_type):
        """
        Enables MFA for this user with the inputted challenge type.

        The enabling process includes setting this objects challenge type and
        generating a new backup key.

        :param challenge_type: Enable MFA for this type of challenge. The type
                               must be in the supported `CHALLENGE_TYPES`.
        :raises AssertionError: If ``challenge_type`` is not a supported
                                challenge type.
        """
        assert challenge_type in CHALLENGE_TYPES, (
            "'{challenge}' is not a valid challenge type.".format(
                challenge=challenge_type)
        )
        self.challenge_type = challenge_type
        self.backup_key = generate_key()
        self.save()

    def disable(self):
        """
        Disables MFA for this user.

        The disabling process includes setting the objects challenge type to
        `DISABLED`, and removing the `backup_key` and `phone_number`.
        """
        self.challenge_type = DISABLED
        self.backup_key = ""
        self.phone_number = ""
        self.save()

    def revoke(self):
        """
        Revoke secret MFA for this user.

        This method generate a new secret_key for this user.
        """
        self.secret_key = pyotp.random_base32()
        self.save()

    def refresh_backup_code(self):
        """
        Refreshes the users backup key and returns a new backup code.

        This method should be used to request new backup codes for the user.
        """
        assert self.enabled, (
            "MFA must be on to run refresh_backup_codes."
        )
        self.backup_key = generate_key()
        self.save()
        return self.backup_code

    def check_and_use_backup_code(self, code):
        """
        Checks if the inputted backup code is correct and disables MFA if
        the code is correct.

        This method should be used for authenticating with a backup code. Using
        a backup code to authenticate disables MFA as a side effect.
        """
        backup = self.backup_code
        if code and constant_time_compare(code, backup):
            self.disable()
            return True
        return False

    def generate_challenge(self, challenge_type):
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
        return dispatch[challenge_type]()

    def verify_challenge_code(self, mfa_code):
        return verify_mfa_code(self.secret_key, mfa_code)

    def _sms_challenge(self):
        """Executes the SMS challenge."""
        code = generate_mfa_code(bin_key=self.secret_key)
        send_sms(self.phone_number, code)

    def _qrcode_challenge(self):
        """Executes your QRCODE challenge method."""
        return

    class Meta:
        abstract = True
