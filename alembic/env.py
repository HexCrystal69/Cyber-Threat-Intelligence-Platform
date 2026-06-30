import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
from src.database import Base
# Import all models to ensure metadata is registered
from src.models.user import User
from src.models.feed import ThreatFeed, FeedExecutionLog, FeedHealthSnapshot
from src.models.ioc import IOC, IOCMetadata, IOCFingerprint
from src.models.job import IngestionJob
from src.models.audit import AuditLog
from src.models.enrichment import IOCEnrichment
from src.models.cache import ThreatCache
from src.models.sighting import IOCSighting
from src.models.correlation import CorrelationGroup, CorrelationEvidence, CorrelationRun, CorrelationSnapshot
from src.models.relationship import IOCRelationship
from src.models.campaign import ThreatCampaign, CampaignIOC, CampaignScoreBreakdown, CampaignTimelineEvent
from src.models.actor import ThreatActor, ActorCampaign
from src.models.timeline import IntelligenceTimelineEvent
from src.models.graph import ThreatGraphSnapshot
from src.models.dlq import DeadLetterEvent
from src.models.reputation import IOCReputationHistory
from src.models.confidence import IOCConfidenceHistory
from src.models.source import ThreatSource, IOCSourceMapping
from src.models.dedup import DuplicateIOCGroup
from src.models.score import ThreatScoreSnapshot
from src.models.replay import ProcessedEvent
from src.models.detection import DetectionRule, DetectionRuleSnapshot, DetectionExecution, DetectionMatch
from src.models.alert import SecurityAlert, AlertEvidence, AlertComment, AlertScoreHistory
from src.models.case import InvestigationCase, CaseAlert, CaseEvidence
from src.models.hunting import HuntingCandidate, HuntingQuery, HuntingExecution, HuntingResult
from src.models.playbook import ResponsePlaybook, PlaybookStep
from src.models.attack import AttackTechnique, DetectionTechnique, CampaignTechnique
from src.models.alert_correlation import AlertCorrelationRun, AlertGroup, AlertGroupMember
from src.models.analyst import AnalystAction
from src.models.coverage import DetectionCoverageSnapshot
from src.models.feedback import AlertFeedback
from src.models.blast_radius import IOCBlastRadiusSnapshot
from src.models.dashboard import SocDashboardSnapshot

target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def get_url():
    return os.getenv("DATABASE_URL", config.get_main_option("sqlalchemy.url"))


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
