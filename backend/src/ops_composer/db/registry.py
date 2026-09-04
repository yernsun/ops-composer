from ops_composer.db.migration_engine import Migration
from ops_composer.db.migrations.audit import AUDIT
from ops_composer.db.migrations.auth import AUTH
from ops_composer.db.migrations.auth_security import AUTH_SECURITY
from ops_composer.db.migrations.core import CORE
from ops_composer.db.migrations.ops_composer import OPS_COMPOSER
from ops_composer.db.migrations.playbooks import PLAYBOOKS

MIGRATIONS: tuple[Migration, ...] = (
    CORE,
    AUTH,
    AUTH_SECURITY,
    OPS_COMPOSER,
    AUDIT,
    PLAYBOOKS,
)
