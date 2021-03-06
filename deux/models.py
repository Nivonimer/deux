from __future__ import absolute_import, unicode_literals

from deux.abstract_models import AbstractMultiFactorAuth, AbstractBackupPhone


class MultiFactorAuth(AbstractMultiFactorAuth):
    """
    class::MultiFactorAuth()

    Blank extension of ``AbstractMultiFactorAuth`` that is used as the
    default model in this package.
    """
    pass


class BackupPhoneAuth(AbstractBackupPhone):
    """
    class::BackupPhoneAuth()

    Blank extension of ``AbstractBackupPhone`` that is used as the
    default model in this package.
    """
    pass
