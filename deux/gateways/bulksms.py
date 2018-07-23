import logging
from urllib.parse import urlencode
from urllib.request import urlopen
from deux.app_settings import mfa_settings

from django.utils.translation import ugettext

from deux.exceptions import BulkSMSMessageError
from deux import strings

logger = logging.getLogger(__name__)


class BulkSMS(object):
    """
    Prints the tokens to the logger. You will have to set the message level of
    the ``deux`` logger to ``INFO`` for them to appear in the console.
    Useful for local development. You should configure your logging like this::
        LOGGING = {
            'version': 1,
            'disable_existing_loggers': False,
            'handlers': {
                'console': {
                    'level': 'DEBUG',
                    'class': 'logging.StreamHandler',
                },
            },
            'loggers': {
                'deux': {
                    'handlers': ['console'],
                    'level': 'INFO',
                }
            }
        }
    """
    @staticmethod
    def make_call(phone_number, token):
        logger.info('Fake call to %s: "Your token is: %s"', phone_number, token)

    @staticmethod
    def send_sms(phone_number, token):
        #logger.info('Fake SMS to %s: "Your token is: %s"', phone_number, token)

        url, params = BulkSMS.generate_urlencoded(phone_number, token)
        f = urlopen(url, params)

        s = f.read()
        result = s.split('|')

        statusCode = result[0]
        statusString = result[1]
        if statusCode != '0':
            raise BulkSMSMessageError()

        f.close()

    @staticmethod
    def generate_urlencoded(phone_number, token):
        url = "https://bulksms.vsms.net/eapi/submission/send_sms/2/2.0"
        body = strings.MFA_CODE_TEXT_MESSAGE.format(code=token)

        params = urlencode({
            'username' : mfa_settings.BULKSMS_USERNAME,
            'password' : mfa_settings.BULKSMS_PASSWORD,
            'message' : body,
            'msisdn' : phone_number
        })

        return url, params
