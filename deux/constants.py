from __future__ import absolute_import, unicode_literals

#: Represents the ``DISABLED`` state of MFA.
DISABLED = ""

#: Represents the state of using ``SMS`` for MFA.
SMS = "sms"

#: Represents the state of using ``QRCODE`` for MFA.
QRCODE = "qrcode"

#: A tuple of all support challenge types.
CHALLENGE_TYPES = (SMS, QRCODE)
