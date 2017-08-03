from __future__ import absolute_import, unicode_literals

import six
from binascii import unhexlify
from mock import patch, MagicMock
import time

from django.test import TestCase
from django_otp.util import random_hex

from deux.app_settings import mfa_settings
from deux.constants import SMS
from deux.services import (
    generate_mfa_code,
    verify_mfa_code,
    TotpAuth,
)
from deux.gateways import send_sms

from .test_base import BaseUserTestCase


class TotpAuthTests(BaseUserTestCase):
    
    def setUp(self):
        self.simpleUserSetup()
        self.mfa = mfa_settings.MFA_MODEL.objects.create(user=self.user1)
        self.mfa.phone_number = "+351962145123"
        self.mfa.save()
    
    def test_generate_mfa_code(self):
        code = generate_mfa_code(bin_key=self.mfa.get_bin_key(SMS))

        self.assertEquals(len(code), mfa_settings.MFA_CODE_NUM_DIGITS)
    
    @patch("deux.services.mfa_settings")
    def test_validate_mfa_code(self, mfa_settings):
        mfa_settings.MFA_CODE_INTERVAL = 2
        mfa_settings.MFA_CODE_NUM_DIGITS = 6
        
        bin_key = self.mfa.get_bin_key(SMS)
        code = TotpAuth(bin_key).generate_token()
        
        # validate now
        time.sleep(1)
        self.assertTrue(TotpAuth(bin_key).valid(code))

        # validate now - MFA_CODE_INTERVAL
        time.sleep(1)
        self.assertTrue(TotpAuth(bin_key).valid(code))
        
        # must be invalid on 4 second
        time.sleep(2)
        self.assertFalse(TotpAuth(bin_key).valid(code))
