from __future__ import absolute_import, unicode_literals

import six

from rest_framework import serializers
from rest_framework.fields import empty

from deux.app_settings import mfa_settings
from deux import strings
from deux.constants import SMS, QRCODE
from deux.exceptions import FailedChallengeError
from deux.services import generate_qrcode_url
from deux.models import BackupPhoneAuth

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse  # < django 1.10

from urllib.parse import quote


class MultiFactorAuthSerializer(serializers.ModelSerializer):
    """
    class::MultiFactorAuthSerializer()

    Basic MultiFactorAuthSerializer that encodes MFA objects into a standard
    response.

    The standard response returns whether MFA is enabled, the challenge
    type, and the user's phone number.
    """

    def to_representation(self, mfa_instance):
        """
        Encodes an MFA instance as the standard response.

        :param mfa_instance: :class:`MultiFactorAuth` instance to use.
        :returns: Dictionary with ``enabled``, ``challengetype``, and
            ``phone_number`` from the MFA instance.
        """
        data = {"enabled": mfa_instance.enabled}
        if mfa_instance.phone_number:
            data["phone_number"] = mfa_instance.get_phone_number()
        if mfa_instance.enabled:
            data["challenge_type"] = mfa_instance.challenge_type
            backup_phones = BackupPhoneAuth.objects.backup_phones_for_user(
                user=self.context['request'].user
            )
            data['backup_phones'] = []
            for backup_phone in backup_phones:
                data['backup_phones'].append({
                    'id': str(backup_phone.pk),
                    'confirmed': backup_phone.confirmed,
                    'method': backup_phone.method,
                    'phone_number': backup_phone.get_phone_number()
                })

        return data

    class Meta:
        model = mfa_settings.MFA_MODEL


class _BaseChallengeRequestSerializer(MultiFactorAuthSerializer):
    """
    class::_BaseChallengeRequestSerializer()

    Base Serializer class for all challenge request.
    """

    @property
    def challenge_type(self):
        """
        Represents the challenge type this serializer represents.

        :raises NotImplemented: If the extending class does not define
            ``challenge_type``.
        """
        raise NotImplementedError  # pragma: no cover

    def execute_challenge(self, instance):
        """
        Execute challenge for this instance based on the ``challenge_type``.

        :param instance: :class:`MultiFactorAuth` instance to use.
        :raises serializers.ValidationError: If the challenge fails to execute.
        """
        try:
            instance.generate_challenge(self.challenge_type)
        except FailedChallengeError as e:
            raise serializers.ValidationError({
                "detail": six.text_type(e)
            })

    def validate(self, internal_data):
        """
        Validate the request to enable MFA through this challenge.

        Extending classes should extend for additional functionality. The
        base functionality ensures that MFA is not already enabled.

        :param internal_data: Dictionary of the request data.
        :raises serializers.ValidationError: If MFA is already enabled.
        """
        if self.instance.enabled:
            raise serializers.ValidationError({
                "detail": strings.ENABLED_ERROR
            })
        return internal_data

    def update(self, mfa_instance, validated_data):
        """
        If the request is valid, the serializer calls update which executes
        the ``challenge_type``.

        :param mfa_instance: :class:`MultiFactorAuth` instance to use.
        :param validated_data: Data returned by ``validate``.
        """
        self.execute_challenge(mfa_instance)


class _BaseChallengeVerifySerializer(MultiFactorAuthSerializer):
    """
    class::_BaseChallengeVerifySerializer()

    This serializer first extracts MFA code from request body
    (`to_internal_value`). It then  verifies the code against the
    corresponding `MultiFactorAuth` instance (`validate`). If the code
    is valid, it enables MFA based on the challenge type (`update`).
    """

    #: Requests to verify an MFA code must include an ``mfa_code``.
    mfa_code = serializers.CharField()

    @property
    def challenge_type(self):
        """
        Represents the challenge type this serializer represents.

        :raises NotImplemented: If the extending class does not define
            ``challenge_type``.
        """
        raise NotImplementedError  # pragma: no cover

    def validate(self, internal_data):
        """
        Validates the request to verify the MFA code. It first ensures that
        MFA is not already enabled and then verifies that the MFA code is the
        correct code.

        :param internal_data: Dictionary of the request data.
        :raises serializers.ValidationError: If MFA is already enabled or if
            the inputted MFA code is not valid.
        """
        if self.instance.enabled:
            raise serializers.ValidationError({
                "detail": strings.ENABLED_ERROR
            })

        mfa_code = internal_data.get("mfa_code")
        if not self.instance.verify_challenge_code(mfa_code):
            raise serializers.ValidationError({
                "mfa_code": strings.INVALID_MFA_CODE_ERROR
            })
        return {"mfa_code": mfa_code}

    def update(self, mfa_instance, validated_data):
        """
        If the request is valid, the serializer enables MFA on this instance
        for this serializer's ``challenge_type``.

        :param mfa_instance: :class:`MultiFactorAuth` instance to use.
        :param validated_data: Data returned by ``validate``.
        """
        mfa_instance.enable(self.challenge_type)
        return mfa_instance

    class Meta(MultiFactorAuthSerializer.Meta):
        fields = ("mfa_code",)


class SMSChallengeRequestSerializer(_BaseChallengeRequestSerializer):
    """
    class::SMSChallengeRequestSerializer()

    Serializer that facilitates a request to enable MFA over SMS.
    """

    #: This serializer represents the ``SMS`` challenge type.
    challenge_type = SMS

    def update(self, mfa_instance, validated_data):
        """
        If the request data is valid, the serializer executes the challenge
        by calling the super method and also saves the phone number the user
        requested the SMS to.

        :param mfa_instance: :class:`MultiFactorAuth` instance to use.
        :param validated_data: Data returned by ``validate``.
        """
        mfa_instance.phone_number = validated_data["phone_number"]
        super(SMSChallengeRequestSerializer, self).update(
            mfa_instance, validated_data)
        mfa_instance.save()
        return mfa_instance

    class Meta(_BaseChallengeRequestSerializer.Meta):
        fields = ("phone_number",)
        extra_kwargs = {
            "phone_number": {
                "required": True,
            },
        }


class SMSChallengeVerifySerializer(_BaseChallengeVerifySerializer):
    """
    class::SMSChallengeVerifySerializer()

    Extension of ``_BaseChallengeVerifySerializer`` that implements
    challenge verification for the SMS challenge.
    """

    #: This serializer represents the ``SMS`` challenge type.
    challenge_type = SMS


class QRCODEChallengeRequestSerializer(_BaseChallengeRequestSerializer):
    """
    class::QRCODEChallengeRequestSerializer()

    Serializer that facilitates a request to enable MFA over QR CODE.
    """

    #: This serializer represents the ``QRCODE`` challenge type.
    challenge_type = QRCODE

    class Meta(_BaseChallengeRequestSerializer.Meta):
        fields = ()

    def update(self, mfa_instance, validated_data):
        super(QRCODEChallengeRequestSerializer, self).update(mfa_instance, validated_data)

        return mfa_instance

    def to_representation(self, mfa_instance):
        data = super(QRCODEChallengeRequestSerializer, self).to_representation(mfa_instance)

        name = self.instance.user.username

        if not name:
            name = self.instance.user.email

        otpauth_url = generate_qrcode_url(
            self.instance.get_bin_key(self.challenge_type),
            name,
            mfa_settings.APP_NAME
        )
        request = self.context['request']

        url = request.build_absolute_uri(
            reverse("deux:" + mfa_settings.QRCODE_GENERATER_URL)) + '?url=' + otpauth_url

        data['qrcode_url'] = quote(url)

        return data


class QRCODEChallengeVerifySerializer(_BaseChallengeVerifySerializer):
    """
    class::QRCODEChallengeVerifySerializer()

    Extension of ``_BaseChallengeVerifySerializer`` that implements
    challenge verification for the QRCODE challenge.
    """

    #: This serializer represents the ``QRCODE`` challenge type.
    challenge_type = QRCODE


class BackupCodeSerializer(serializers.ModelSerializer):
    """
    class::BackupCodeSerializer()

    Serializer for the user requesting backup codes.
    """

    #: Serializer field for the backup code.
    backup_code = serializers.SerializerMethodField()

    def get_backup_code(self, instance):
        """
        Method for retrieving the backup code. On every request, the backup
        code is refreshed.

        :param instance: :class:`MultiFactorAuth` instance to use.
        :raises serializers.ValidationError: If MFA is disabled.
        """
        if self.instance.enabled:
            return self.instance.refresh_backup_code()
        else:
            raise serializers.ValidationError({
                "backup_code": strings.DISABLED_ERROR
            })

    class Meta:
        model = mfa_settings.MFA_MODEL
        fields = ("backup_code",)


class BackupPhoneSerializer(serializers.ModelSerializer):
    """
    class::BackupPhoneSerializer()

    Basic BackupPhoneSerializer that encodes MFA objects into a standard
    response.

    The standard response returns whether MFA is enabled, the challenge
    type, and the user's phone number.
    """

    class Meta:
        model = BackupPhoneAuth

    def run_validation(self, data=empty):
        user = self.context['request'].user
        mfa = getattr(user, "multi_factor_auth", None)

        if not mfa or not mfa.enabled:
            raise serializers.ValidationError({
                "detail": strings.DISABLED_ERROR
            })

        return super(BackupPhoneSerializer, self).run_validation(data)


class BackupPhoneCreateSerializer(BackupPhoneSerializer):
    """
    class::BackupPhoneCreateSerializer()

    Serializer that facilitates a request to enable Backup Phone.
    """

    class Meta(BackupPhoneSerializer.Meta):
        fields = ("phone_number", "method", )
        extra_kwargs = {
            "phone_number": {
                "required": True,
            },
        }

    def validate(self, internal_data):
        user_phones = BackupPhoneAuth.objects.backup_phones_for_user(
            user=self.context['request'].user
        )
        phone_exists = user_phones.filter(phone_number=internal_data.get('phone_number'))

        if phone_exists.count() > 0:
            raise serializers.ValidationError({
                "detail": "Phone number already exists."
            })

        # TODO: Validate number for allow resend code for one was confirmed
        if user_phones.count() >= mfa_settings.MAX_BACKUP_PHONE_NUMBERS:
            raise serializers.ValidationError({
                "detail": "Limit of phone numbers is {}".format(
                    mfa_settings.MAX_BACKUP_PHONE_NUMBERS)
            })

        return super(BackupPhoneCreateSerializer, self).validate(internal_data)

    def create(self, validated_data):
        """Executes the SMS challenge."""
        instance = BackupPhoneAuth.objects.create(
            user=self.context['request'].user,
            **validated_data
        )
        instance.generate_challenge()

        return instance

    def to_representation(self, instance):
        return {
            "id": str(instance.pk),
            "phone_number": instance.get_phone_number(),
            "method": instance.method
        }


class BackupPhoneRequestSerializer(BackupPhoneSerializer):
    """
    class::BackupPhoneRequestSerializer()

    Serializer that facilitates a request to enable Backup Phone.
    """

    class Meta(BackupPhoneSerializer.Meta):
        fields = ()

    def validate(self, internal_data):
        if self.instance.confirmed:
            raise serializers.ValidationError({
                "detail": strings.ENABLED_ERROR
            })

        return {}

    def update(self, instance, validated_data):
        instance.generate_challenge()

        return instance

    def to_representation(self, instance):
        return {
            "id": str(instance.pk),
            "phone_number": instance.get_phone_number()
        }


class BackupPhoneVerifySerializer(BackupPhoneSerializer):
    """
    class::BackupPhoneVerifySerializer()

    Serializer that facilitates a request to enable MFA over QR CODE.
    """

    #: Requests to verify an MFA code must include an ``mfa_code``.
    mfa_code = serializers.CharField()

    class Meta(BackupPhoneSerializer.Meta):
        fields = ("mfa_code",)

    def validate(self, internal_data):
        if self.instance.confirmed:
            raise serializers.ValidationError({
                "detail": "Backup Phone is already confirmed."
            })

        mfa_code = internal_data.get("mfa_code")
        if not self.instance.verify_challenge_code(mfa_code):
            raise serializers.ValidationError({
                "mfa_code": strings.INVALID_MFA_CODE_ERROR
            })

        return {}

    def update(self, instance, validated_data):
        instance.confirmed = True
        instance.save()

        return instance

    def to_representation(self, instance):
        return {
            "confirmed": instance.confirmed
        }
