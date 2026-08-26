from __future__ import annotations

from typing import Any

from alembic.ddl.postgresql import PostgresqlImpl
from sqlalchemy import String, inspect
from sqlalchemy.engine import Connection
from sqlalchemy.sql.schema import Table

VERSION_NUM_LENGTH = 64


class VyperPostgresqlImpl(PostgresqlImpl):
	"""Create Alembic's PostgreSQL version table with room for VYPER revisions."""

	__dialect__ = "postgresql"

	def version_table_impl(self, **kwargs: Any) -> Table:
		table = super().version_table_impl(**kwargs)
		table.c.version_num.type = String(VERSION_NUM_LENGTH)
		return table


def ensure_postgresql_version_table_compatibility(
	connection: Connection, *, table_name: str = "alembic_version", schema: str | None = None,
) -> None:
	"""Create or widen the PostgreSQL version table before Alembic stamps a revision."""
	if connection.dialect.name != "postgresql":
		return
	implementation = VyperPostgresqlImpl(
		connection.dialect, connection, False, None, None, {},
	)
	table = implementation.version_table_impl(
		version_table=table_name, version_table_schema=schema, version_table_pk=True,
	)
	inspector = inspect(connection)
	if table_name not in inspector.get_table_names(schema=schema):
		table.create(connection)
		return
	column = next((item for item in inspector.get_columns(table_name, schema=schema)
		if item["name"] == "version_num"), None)
	if column is None:
		raise RuntimeError(f"{table_name} exists without required version_num column")
	length = getattr(column["type"], "length", None)
	if length is None or length >= VERSION_NUM_LENGTH:
		return
	preparer = connection.dialect.identifier_preparer
	qualified_table = preparer.quote(table_name)
	if schema:
		qualified_table = f"{preparer.quote_schema(schema)}.{qualified_table}"
	connection.exec_driver_sql(
		f"ALTER TABLE {qualified_table} ALTER COLUMN version_num TYPE VARCHAR({VERSION_NUM_LENGTH})"
	)
