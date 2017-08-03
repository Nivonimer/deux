import logging

logger = logging.getLogger(__name__)

from deux import strings


class Fake(object):
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
        message = strings.MFA_CODE_TEXT_MESSAGE.format(code=token)
        logger.info('Fake SMS to %s: "%s"', phone_number, message)
