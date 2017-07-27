# -*- coding: utf-8 -*-
from django.utils.module_loading import import_string

from deux.app_settings import mfa_settings


def get_gateway_class(import_path):
    return import_string(import_path)


def make_call(phone_number, token):
    gateway = get_gateway_class(getattr(mfa_settings, 'TWO_FACTOR_CALL_GATEWAY'))()
    gateway.make_call(phone_number=phone_number, token=token)


def send_sms(phone_number, token):
    gateway = get_gateway_class(getattr(mfa_settings, 'TWO_FACTOR_SMS_GATEWAY'))()
    gateway.send_sms(phone_number=phone_number, token=token)
