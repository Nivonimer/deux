from __future__ import absolute_import, unicode_literals

import six
from binascii import unhexlify
from mock import patch

from django.test import TestCase
from django_otp.util import random_hex

from deux.app_settings import mfa_settings
from deux.constants import SMS
from deux.services import (
    generate_mfa_code,
    verify_mfa_code,
)

from .test_base import BaseUserTestCase


