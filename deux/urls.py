from __future__ import absolute_import, unicode_literals

from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns

from deux import views

urlpatterns = [
    url(r"^$", views.MultiFactorAuthDetail.as_view(),
        name="multi_factor_auth-detail"),

    # SMS
    url(r"^sms/request/$", views.SMSChallengeRequestDetail.as_view(),
        name="sms_request-detail"),
    url(r"^sms/verify/$", views.SMSChallengeVerifyDetail.as_view(),
        name="sms_verify-detail"),

    # QRCODE
    url(r"^qrcode/request/$", views.QRCODEChallengeRequestDetail.as_view(),
        name="qrcode_request-detail"),
    url(r"^qrcode/verify/$", views.QRCODEChallengeVerifyDetail.as_view(),
        name="qrcode_verify-detail"),
    url(r"^qrcode/generate/$", views.QRCODEGeneratorView.as_view(),
        name="qrcode_generate-detail"),

    # BACKUP PHONE NUMBERS
    url(r"^backup-phone/request/$", views.BackupPhoneRequestDetail.as_view(),
        name="backup-phone_request-detail"),
    url(r"^backup-phone/verify/$", views.BackupPhoneVerifyDetail.as_view(),
        name="backup-phone_verify-detail"),

    url(r"^recovery/$", views.BackupCodeDetail.as_view(),
        name="backup_code-detail"),
]

urlpatterns = format_suffix_patterns(urlpatterns)
