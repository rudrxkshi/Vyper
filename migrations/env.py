from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from backend.app.db import Base
from backend.app import models  # noqa: F401
from migrations.version_table import ensure_postgresql_version_table_compatibility

config = context.config
if config.config_file_name is not None:
	fileConfig(config.config_file_name)
if os.getenv("VYPER_DATABASE_URL"):
	config.set_main_option("sqlalchemy.url", os.environ["VYPER_DATABASE_URL"].replace("%", "%%"))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
	context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata, literal_binds=True,
		dialect_opts={"paramstyle": "named"}, compare_type=True)
	with context.begin_transaction():
		context.run_migrations()


def run_migrations_online() -> None:
	connectable = engine_from_config(config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.",
		poolclass=pool.NullPool, future=True)
	with connectable.connect() as connection:
		if connection.dialect.name == "postgresql":
			with connection.begin():
				ensure_postgresql_version_table_compatibility(connection)
		context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
		with context.begin_transaction():
			context.run_migrations()


run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
