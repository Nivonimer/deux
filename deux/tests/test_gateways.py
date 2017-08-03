from __future__ import absolute_import, unicode_literals

import six
from binascii import unhexlify
from mock import patch, MagicMock

from django.test import TestCase
from django_otp.util import random_hex

from deux.app_settings import mfa_settings
from deux.constants import SMS
from deux.services import (
    generate_mfa_code,
    verify_mfa_code,
)
from deux.gateways import send_sms

from .test_base import BaseUserTestCase
from deux.gateways.bulksms import BulkSMS
from deux.exceptions import BulkSMSMessageError


class BulkSMSGatewayTests(BaseUserTestCase):
    
    def setUp(self):
        self.simpleUserSetup()
        self.mfa = mfa_settings.MFA_MODEL.objects.create(user=self.user1)
        self.mfa.phone_number = "+351962145123"
        self.mfa.save()
        self.code = "123456"
    
    @patch("deux.gateways.bulksms.mfa_settings")
    @patch("deux.gateways.mfa_settings")
    def test_success(self, gateways_mfa_settings, bulksms_mfa_settings):
        gateways_mfa_settings.TWO_FACTOR_SMS_GATEWAY = "deux.gateways.bulksms.BulkSMS"
        bulksms_mfa_settings.BULKSMS_USERNAME = "authtoken"
        bulksms_mfa_settings.BULKSMS_PASSWORD = "0987654321"

        mock_urlopen_patcher = patch('deux.gateways.bulksms.urlopen')
        mock_sendsms = mock_urlopen_patcher.start()
        cm = MagicMock()
        cm.read.return_value = "0|test"
        mock_sendsms.return_value = cm

        code = generate_mfa_code(bin_key=self.mfa.get_bin_key(SMS))
        send_sms(self.mfa.phone_number, code)

        url, params = BulkSMS.generate_urlencoded(self.mfa.phone_number, code)
        mock_sendsms.assert_called_once_with(url, params)

    @patch("deux.gateways.bulksms.mfa_settings")
    @patch("deux.gateways.mfa_settings")
    def test_failed_sms_error(self, gateways_mfa_settings, bulksms_mfa_settings):
        gateways_mfa_settings.TWO_FACTOR_SMS_GATEWAY = "deux.gateways.bulksms.BulkSMS"
        bulksms_mfa_settings.BULKSMS_USERNAME = "authtoken"
        bulksms_mfa_settings.BULKSMS_PASSWORD = "0987654321"

        mock_urlopen_patcher = patch('deux.gateways.bulksms.urlopen')
        mock_sendsms = mock_urlopen_patcher.start()
        cm = MagicMock()
        cm.read.return_value = "1|test"
        mock_sendsms.return_value = cm

        code = generate_mfa_code(bin_key=self.mfa.get_bin_key(SMS))
        with self.assertRaises(BulkSMSMessageError):
            send_sms(self.mfa.phone_number, code)

        url, params = BulkSMS.generate_urlencoded(self.mfa.phone_number, code)
        mock_sendsms.assert_called_once_with(url, params)
