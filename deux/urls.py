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
    url(r"^backupphone/$", views.BackupPhoneCreate.as_view(),
        name="backupphone-create"),
    url(r"^backupphone/(?P<backupphone_id>[0-9a-z-]+)/verify/$",
        views.BackupPhoneVerifyDetail.as_view(),
        name="backupphone_verify-detail"),
    url(r"^backupphone/(?P<backupphone_id>[0-9a-z-]+)/request/$",
        views.BackupPhoneRequestDetail.as_view(),
        name="backupphone_request-detail"),
    url(r"^backupphone/(?P<backupphone_id>[0-9a-z-]+)/$",
        views.BackupPhoneDelete.as_view(),
        name="backupphone-delete"),

    url(r"^recovery/$", views.BackupCodeDetail.as_view(),
        name="backup_code-detail"),
]

urlpatterns = format_suffix_patterns(urlpatterns)
