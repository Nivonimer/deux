# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import qrcode

from rest_framework import generics
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from django.views.generic.base import View
from django.http import HttpResponse, Http404
from django.utils.translation import ugettext_lazy as _

from deux import strings
from deux.app_settings import mfa_settings, import_from_string
from deux.constants import SMS, QRCODE
from deux.models import BackupPhoneAuth
from deux.serializers import (
    BackupCodeSerializer,
    MultiFactorAuthSerializer,
    # SMS
    SMSChallengeRequestSerializer,
    SMSChallengeVerifySerializer,
    # QRCODE
    QRCODEChallengeRequestSerializer,
    QRCODEChallengeVerifySerializer,
    # Backup Phone
    BackupPhoneCreateSerializer,
    BackupPhoneRequestSerializer,
    BackupPhoneVerifySerializer
)


class MultiFactorAuthMixin(object):
    """
    class::MultiFactorAuthMixin()

    Mixin that defines queries for MFA objects.
    """

    def get_object(self):
        """Gets the current user's MFA instance"""
        instance, created = mfa_settings.MFA_MODEL.objects.get_or_create(
            user=self.request.user)
        return instance


class MultiFactorAuthDetail(
        MultiFactorAuthMixin, generics.RetrieveDestroyAPIView):
    """
    class::MultiFactorAuthDetail()

    View for requesting data about MultiFactorAuth and disabling MFA.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = MultiFactorAuthSerializer

    def perform_destroy(self, instance):
        """
        The delete method should disable MFA for this user.

        :raises rest_framework.exceptions.ValidationError: If MFA is not
            enabled.
        """
        if 'revoke' in self.request.GET:
            instance.revoke()

        if not instance.enabled:
            raise ValidationError({
                "detail": strings.DISABLED_ERROR
            })
        instance.disable()

        # delete all backup phones
        BackupPhoneAuth.objects.backup_phones_for_user(
            user=self.request.user
        ).delete()


class _BaseChallengeView(MultiFactorAuthMixin, generics.UpdateAPIView):
    """
    class::_BaseChallengeView()

    Base view for different challenges.
    """
    permission_classes = (IsAuthenticated,)

    @property
    def challenge_type(self):
        """
        Represents the challenge type this serializer represents.

        :raises NotImplemented: If the extending class does not define
            ``challenge_type``.
        """
        raise NotImplemented  # pragma: no cover


class SMSChallengeRequestDetail(_BaseChallengeView):
    """
    class::SMSChallengeRequestDetail()

    View for requesting SMS challenges to enable MFA through SMS.
    """
    challenge_type = SMS
    serializer_class = SMSChallengeRequestSerializer


class SMSChallengeVerifyDetail(_BaseChallengeView):
    """
    class::SMSChallengeVerifyDetail()

    View for verify SMS challenges to enable MFA through SMS.
    """
    challenge_type = SMS
    serializer_class = SMSChallengeVerifySerializer


class QRCODEChallengeRequestDetail(_BaseChallengeView):
    """
    class::QRCODEChallengeRequestDetail()

    View for requesting QRCODE challenges to enable MFA through QR Code.
    """
    challenge_type = QRCODE
    serializer_class = QRCODEChallengeRequestSerializer


class QRCODEChallengeVerifyDetail(_BaseChallengeView):
    """
    class::QRCODEChallengeVerifyDetail()

    View for verify QRCODE challenges to enable MFA through QR Code.
    """
    challenge_type = QRCODE
    serializer_class = QRCODEChallengeVerifySerializer


class BackupCodeDetail(MultiFactorAuthMixin, generics.RetrieveAPIView):
    """
    class::BackupCodeDetail()

    View for retrieving the user's backup code.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = BackupCodeSerializer


class QRCODEGeneratorView(View):
    """
    View returns an SVG image with the OTP token information
    """
    http_method_names = ['get']
    default_qr_factory = 'qrcode.image.svg.SvgPathImage'

    # The qrcode library only supports PNG and SVG for now
    image_content_types = {
        'PNG': 'image/png',
        'SVG': 'image/svg+xml; charset=utf-8',
    }

    def get(self, request, *args, **kwargs):

        # Get data for qrcode
        image_factory_string = getattr(mfa_settings, 'TWO_FACTOR_QR_FACTORY', self.default_qr_factory)
        image_factory = import_from_string(image_factory_string, 'TWO_FACTOR_QR_FACTORY')
        content_type = self.image_content_types[image_factory.kind]

        if 'url' not in request.GET:
            raise Http404()

        otpauth_url = request.GET['url']
        # Make and return QR code

        img = qrcode.make(otpauth_url, image_factory=image_factory)
        resp = HttpResponse(content_type=content_type)
        img.save(resp)
        return resp


class BackupPhoneChallengeMixin(object):
    """
    class::BackupPhoneChallengeMixin()

    Mixin that defines queries for MFA objects.
    """
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        """Gets the current user's MFA instance"""
        
        backupphone_id = self.kwargs['backupphone_id']
        results = BackupPhoneAuth.objects.backup_phones_for_user(
            user=self.request.user
        )
        results = results.filter(pk=backupphone_id)

        if results.count() == 0:
            raise Http404

        return results[0]


class BackupPhoneCreate(BackupPhoneChallengeMixin, generics.CreateAPIView):
    """
    class::BackupPhoneRequestDetail()

    View for retrieving the user's backup code.
    """
    serializer_class = BackupPhoneCreateSerializer


class BackupPhoneRequestDetail(BackupPhoneChallengeMixin, generics.UpdateAPIView):
    """
    class::BackupPhoneVerifyDetail()

    View for retrieving the user's backup code.
    """
    serializer_class = BackupPhoneRequestSerializer


class BackupPhoneVerifyDetail(BackupPhoneChallengeMixin, generics.UpdateAPIView):
    """
    class::BackupPhoneVerifyDetail()

    View for retrieving the user's backup code.
    """
    serializer_class = BackupPhoneVerifySerializer


class BackupPhoneDelete(BackupPhoneChallengeMixin, generics.DestroyAPIView):
    """
    class::BackupPhoneDelete()  

    View for retrieving the user's backup code.
    """
