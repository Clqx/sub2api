from pathlib import Path

import sqlalchemy as sa
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory


def test_cost_gate_migration_preserves_policies_and_round_trips():
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parents[1] / "alembic"))
    script = ScriptDirectory.from_config(config)
    assert script.get_current_head() == "ab71c4e20319"
    migration = script.get_revision("ab71c4e20319").module
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE targets (id VARCHAR(36) PRIMARY KEY)")
            connection.exec_driver_sql(
                "CREATE TABLE cost_routing_policies (id VARCHAR(36) PRIMARY KEY, enabled BOOLEAN)"
            )
            connection.exec_driver_sql("INSERT INTO cost_routing_policies VALUES ('existing', 1)")
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                assert connection.exec_driver_sql(
                    "SELECT id, enabled, maximum_multiplier FROM cost_routing_policies"
                ).one() == ("existing", 1, 1.0)
                assert "routing_usage_cursors" in sa.inspect(connection).get_table_names()
                columns = sa.inspect(connection).get_columns("routing_usage_cursors")
                assert {col["name"] for col in columns} >= {
                    "target_id", "last_usage_id", "lease_owner", "lease_until", "next_run_at"
                }
                migration.downgrade()
                assert "routing_usage_cursors" not in sa.inspect(connection).get_table_names()
                assert connection.exec_driver_sql(
                    "SELECT id, enabled FROM cost_routing_policies"
                ).one() == ("existing", 1)
                migration.upgrade()
                assert connection.exec_driver_sql(
                    "SELECT maximum_multiplier FROM cost_routing_policies"
                ).scalar_one() == 1.0
    finally:
        engine.dispose()
