from __future__ import absolute_import, unicode_literals

from mock import patch

from django.urls import reverse
from rest_framework import status

from deux.app_settings import mfa_settings
from deux.constants import DISABLED, SMS, QRCODE
from deux.exceptions import FailedChallengeError
from deux.services import generate_mfa_code
from deux import strings
from deux.abstract_models import phone_mask

from .test_base import BaseUserTestCase
from deux.models import BackupPhoneAuth


class _BaseMFAViewTest(BaseUserTestCase):

    def setUp(self):
        self.simpleUserSetup()
        self.mfa_1 = mfa_settings.MFA_MODEL.objects.create(user=self.user1)
        self.mfa_2 = mfa_settings.MFA_MODEL.objects.create(user=self.user2)
        self.mfa_2.enable(SMS)
        self.phone_number = "+351962457123"
        self.mfa_2.phone_number = self.phone_number
        self.mfa_2.save()


class MultiFactorAuthViewTest(_BaseMFAViewTest):
    url = reverse("deux:multi_factor_auth-detail")

    def test_get(self):
        # Check for HTTP401.
        self.check_get_response(self.url, status.HTTP_403_FORBIDDEN)

        # Check for HTTP200 - MFA for a disabled user.
        resp = self.check_get_response(
            self.url, status.HTTP_200_OK, user=self.user1
        )
        resp_json = resp.data
        self.assertEqual(resp_json["enabled"], False)
        with self.assertRaises(KeyError):
            resp_json["challenge_type"]

        # Check for HTTP200 - MFA Enabled User.
        resp = self.check_get_response(
            self.url, status.HTTP_200_OK, user=self.user2
        )
        resp_json = resp.data
        self.assertEqual(resp_json["enabled"], True)
        self.assertEqual(resp_json["challenge_type"], SMS)

    def test_delete(self):
        # Check for HTTP401.
        self.check_delete_response(self.url, status.HTTP_403_FORBIDDEN)

        # Check for HTTP400 - MFA for a disabled user.
        resp = self.check_delete_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user1)
        self.assertEqual(resp.data, {
            "detail": strings.DISABLED_ERROR
        })

        # Check for HTTP200.
        self.mfa_2.refresh_backup_code()
        self.check_delete_response(
            self.url, status.HTTP_204_NO_CONTENT, user=self.user2)
        instance = mfa_settings.MFA_MODEL.objects.get(user=self.user2)
        self.assertFalse(instance.enabled)
        self.assertEqual(instance.challenge_type, DISABLED)
        self.assertEqual(instance.backup_code, "")
        self.assertEqual(instance.phone_number, "")


class SMSChallengeRequestViewTest(_BaseMFAViewTest):
    url = reverse("deux:sms_request-detail")

    def test_unauthorized(self):
        self.check_put_response(self.url, status.HTTP_403_FORBIDDEN)

    def test_already_enabled(self):
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user2,
            data={"phone_number": self.phone_number})
        self.assertEqual(resp.data, {"detail": [strings.ENABLED_ERROR]})

    def test_bad_phone_numbers(self):
        # No phone number inputted.
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user1)
        self.assertEqual(resp.data, {
            "phone_number": ["This field is required."]
        })

        # Invalid phone number.
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user1,
            data={"phone_number": "bad_number"})
        self.assertEqual(resp.data, {
            "phone_number": ["The phone number entered is not valid."]
        })

    def test_pt_phone_numbers(self):
        # valid phone number.
        resp = self.check_put_response(
            self.url, status.HTTP_200_OK, user=self.user1,
            data={"phone_number": "+351962135612"})

        # invalid phone number.
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user1,
            data={"phone_number": "+351982135612"})
        self.assertEqual(resp.data, {
            "phone_number": ["The phone number entered is not valid."]
        })

    def test_es_phone_numbers(self):
        # valid phone number.
        resp = self.check_put_response(
            self.url, status.HTTP_200_OK, user=self.user1,
            data={"phone_number": "+34749159049"})

        # invalid phone number.
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user1,
            data={"phone_number": "+34000123456"})
        self.assertEqual(resp.data, {
            "phone_number": ["The phone number entered is not valid."]
        })

    def test_fr_phone_numbers(self):
        # valid phone number.
        resp = self.check_put_response(
            self.url, status.HTTP_200_OK, user=self.user1,
            data={"phone_number": "+330623124554"})

        # invalid phone number.
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user1,
            data={"phone_number": "+331623124554"})
        self.assertEqual(resp.data, {
            "phone_number": ["The phone number entered is not valid."]
        })

    '''
    def test_failed_sms_error(self, challenge):
        challenge.return_value.generate_challenge.side_effect = (
            FailedChallengeError("Error Message."))
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user1,
            data={"phone_number": self.phone_number})
        self.assertEqual(resp.data, {
            "detail": "Error Message."
        })'''

    def test_success(self):
        resp = self.check_put_response(
            self.url, status.HTTP_200_OK, user=self.user1,
            data={"phone_number": self.phone_number})
        self.assertEqual(resp.data, {
            "enabled": False, "phone_number": phone_mask.sub('*', self.phone_number)
        })
        self.mfa_1.generate_challenge(SMS)


class SMSChallengeVerifyViewTest(_BaseMFAViewTest):
    url = reverse("deux:sms_verify-detail")

    def test_unauthorized(self):
        self.check_put_response(self.url, status.HTTP_403_FORBIDDEN)

    def test_already_enabled(self):
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user2,
            data={"mfa_code": "code"})
        self.assertEqual(resp.data, {"detail": [strings.ENABLED_ERROR]})

    def test_incorrect_mfa_codes(self):
        # Check for failure with incorrect mfa_code.
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user1,
            data={"mfa_code": "545464"}
        )
        self.assertEqual(resp.data, {
            "mfa_code": [strings.INVALID_MFA_CODE_ERROR]
        })

        # Check for failure with None mfa_code.
        self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST,
            user=self.user1, data=None
        )
        self.assertEqual(resp.data, {
            "mfa_code": [strings.INVALID_MFA_CODE_ERROR]
        })

    def test_success(self):
        mfa_code = generate_mfa_code(self.mfa_1.get_bin_key(SMS))
        resp = self.check_put_response(
            self.url, status.HTTP_200_OK, user=self.user1,
            data={"mfa_code": mfa_code}
        )
        resp_json = resp.data
        self.assertEqual(resp_json["enabled"], True)
        self.assertEqual(resp_json["challenge_type"], SMS)
        instance = mfa_settings.MFA_MODEL.objects.get(user=self.user1)
        self.assertTrue(instance.enabled)
        self.assertEqual(instance.challenge_type, SMS)


class QRCODEChallengeRequestViewTest(_BaseMFAViewTest):
    url = reverse("deux:qrcode_request-detail")

    def test_unauthorized(self):
        self.check_put_response(self.url, status.HTTP_403_FORBIDDEN)

    def test_already_enabled(self):
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user2,
            data={"mfa_code": "code"})
        self.assertEqual(resp.data, {"detail": [strings.ENABLED_ERROR]})

    def test_success(self):
        resp = self.check_put_response(
            self.url, status.HTTP_200_OK, user=self.user1)
        self.assertIn('qrcode_url', resp.data)
        self.mfa_1.generate_challenge(QRCODE)


class QRCODEChallengeVerifyViewTest(_BaseMFAViewTest):
    url = reverse("deux:qrcode_verify-detail")

    def test_unauthorized(self):
        self.check_put_response(self.url, status.HTTP_403_FORBIDDEN)

    def test_already_enabled(self):
        resp = self.check_put_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user2,
            data={"mfa_code": "code"})
        self.assertEqual(resp.data, {"detail": [strings.ENABLED_ERROR]})

    def test_success(self):
        mfa_code = generate_mfa_code(self.mfa_1.get_bin_key(QRCODE))
        resp = self.check_put_response(
            self.url, status.HTTP_200_OK, user=self.user1,
            data={"mfa_code": mfa_code}
        )
        resp_json = resp.data
        self.assertEqual(resp_json["enabled"], True)
        self.assertEqual(resp_json["challenge_type"], QRCODE)
        instance = mfa_settings.MFA_MODEL.objects.get(user=self.user1)
        self.assertTrue(instance.enabled)
        self.assertEqual(instance.challenge_type, QRCODE)


class BackupCodesViewTest(_BaseMFAViewTest):
    url = reverse("deux:backup_code-detail")

    def test_get(self):
        # Check for HTTP403.
        self.check_get_response(self.url, status.HTTP_403_FORBIDDEN)

        # Check for HTTP400 - MFA for a disabled user.
        resp = self.check_get_response(
            self.url, status.HTTP_400_BAD_REQUEST, user=self.user1)
        self.assertEqual(resp.data, {
            "backup_code": strings.DISABLED_ERROR
        })

        # Check for HTTP200.
        resp = self.check_get_response(
            self.url, status.HTTP_200_OK, user=self.user2)
        self.assertEqual(
            len(resp.data["backup_code"]), mfa_settings.BACKUP_CODE_DIGITS)


class BackupPhonesViewTest(_BaseMFAViewTest):
    url_create = reverse("deux:backupphone-create")
    mfa_url = reverse("deux:multi_factor_auth-detail")

    def url_request(self, backupphone_id):
        return reverse("deux:backupphone_request-detail", kwargs={"backupphone_id": backupphone_id})

    def url_verify(self, backupphone_id):
        return reverse("deux:backupphone_verify-detail", kwargs={"backupphone_id": backupphone_id})

    def url_delete(self, backupphone_id):
        return reverse("deux:backupphone-delete", kwargs={"backupphone_id": backupphone_id})

    def test_create_backup_phone_with_mfa_disable(self):
        # Check for HTTP403.
        self.check_post_response(self.url_create, status.HTTP_403_FORBIDDEN)

        # Check for HTTP400 - MFA for a disabled user.
        resp = self.check_post_response(
            self.url_create, status.HTTP_400_BAD_REQUEST, user=self.user1)
        self.assertEqual(resp.data, {
            "detail": strings.DISABLED_ERROR
        })

    def test_create_backup_phone(self):
        # Check for HTTP403.
        self.check_post_response(self.url_create, status.HTTP_403_FORBIDDEN)

        # Check for HTTP400 - Phone Number is Required
        resp = self.check_post_response(
            self.url_create, status.HTTP_400_BAD_REQUEST, user=self.user2)
        self.assertEqual(resp.data, {
            "phone_number": ["This field is required."]
        })

        # Check for HTTP201 - Create Phone Number
        resp = self.check_post_response(
            self.url_create, status.HTTP_201_CREATED, user=self.user2,
            data={"phone_number": "+351962457123"}
        )
        self.assertIn('method', resp.data)
        self.assertIn('id', resp.data)
        self.assertIn('phone_number', resp.data)

    def test_create_duplicated_backup_phone(self):
        # Check for HTTP201 - Create Phone Number
        resp = self.check_post_response(
            self.url_create, status.HTTP_201_CREATED, user=self.user2,
            data={"phone_number": "+351962457123"}
        )

        # Check for HTTP400 - Try Create Duplicated Phone Number
        resp = self.check_post_response(
            self.url_create, status.HTTP_400_BAD_REQUEST, user=self.user2,
            data={"phone_number": "+351962457123"}
        )
        self.assertEqual(resp.data, {
            "detail": ["Phone number already exists."]
        })

    def test_exceed_max_backup_phones(self):
        for i in range(0, mfa_settings.MAX_BACKUP_PHONE_NUMBERS):
            resp = self.check_post_response(
                self.url_create, status.HTTP_201_CREATED, user=self.user2,
                data={"phone_number": "+35196245712" + str(i)}
            )

        # Check for HTTP400 - Try Exceed Max Backup Phone Numbers
        resp = self.check_post_response(
            self.url_create, status.HTTP_400_BAD_REQUEST, user=self.user2,
            data={"phone_number": "+351962457124"}
        )
        self.assertEqual(resp.data, {
            "detail": ["Limit of phone numbers is {0}".format(mfa_settings.MAX_BACKUP_PHONE_NUMBERS)]
        })

    def test_request_backup_phone(self):
        # Check for HTTP201 - Create Phone Number
        resp = self.check_post_response(
            self.url_create, status.HTTP_201_CREATED, user=self.user2,
            data={"phone_number": "+351962457123"}
        )
        backupphone_id = resp.data['id']

        # Check for HTTP403.
        self.check_put_response(self.url_request(backupphone_id), status.HTTP_403_FORBIDDEN)

        # Check for HTTP200 - Verified backup phone
        resp = self.check_put_response(
            self.url_request(backupphone_id), status.HTTP_200_OK, user=self.user2
        )

        self.assertIn('id', resp.data)
        self.assertIn('phone_number', resp.data)

    def test_verify_backup_phone(self):
        # Check for HTTP201 - Create Phone Number
        resp = self.check_post_response(
            self.url_create, status.HTTP_201_CREATED, user=self.user2,
            data={"phone_number": "+351962457123"}
        )
        backupphone_id = resp.data['id']

        backup_phone = BackupPhoneAuth.objects.get(pk=backupphone_id)
        mfa_code = generate_mfa_code(bin_key=backup_phone.bin_key)

        # Check for HTTP403.
        self.check_put_response(self.url_request(backupphone_id), status.HTTP_403_FORBIDDEN)

        # Check for HTTP200 - Verified backup phone
        resp = self.check_put_response(
            self.url_verify(backupphone_id), status.HTTP_200_OK, user=self.user2,
            data={"mfa_code": mfa_code}
        )
        self.assertEqual(resp.data, {
            "confirmed": True
        })

        # Check for HTTP200 - List Backup Phones on MFA details endpoint
        resp = self.check_get_response(
            self.mfa_url, status.HTTP_200_OK, user=self.user2
        )
        resp_json = resp.data
        self.assertEqual(resp_json["enabled"], True)
        self.assertEqual(resp_json["challenge_type"], SMS)
        self.assertEqual(len(resp_json["backup_phones"]), 1)

    def test_verify_confirmed_backup_phone(self):
        # Check for HTTP201 - Create Phone Number
        resp = self.check_post_response(
            self.url_create, status.HTTP_201_CREATED, user=self.user2,
            data={"phone_number": "+351962457123"}
        )
        backupphone_id = resp.data['id']

        backup_phone = BackupPhoneAuth.objects.get(pk=backupphone_id)
        mfa_code = generate_mfa_code(bin_key=backup_phone.bin_key)

        # Check for HTTP200 - Verified backup phone
        resp = self.check_put_response(
            self.url_verify(backupphone_id), status.HTTP_200_OK, user=self.user2,
            data={"mfa_code": mfa_code}
        )
        self.assertEqual(resp.data, {
            "confirmed": True
        })

        # Check for HTTP400 - Try Verify again backup phone
        resp = self.check_put_response(
            self.url_verify(backupphone_id), status.HTTP_400_BAD_REQUEST, user=self.user2,
            data={"mfa_code": mfa_code}
        )
        self.assertEqual(resp.data, {
            "detail": ["Backup Phone is already confirmed."]
        })

    def test_delete_backup_phone(self):
        # Check for HTTP201 - Create Phone Number
        resp = self.check_post_response(
            self.url_create, status.HTTP_201_CREATED, user=self.user2,
            data={"phone_number": "+351962457123"}
        )
        backupphone_id = resp.data['id']

        # Check for HTTP403.
        self.check_delete_response(self.url_request(backupphone_id), status.HTTP_403_FORBIDDEN)

        # Check for HTTP204 - Try Delete created backup phone
        resp = self.check_delete_response(
            self.url_delete(backupphone_id), status.HTTP_204_NO_CONTENT, user=self.user2)
