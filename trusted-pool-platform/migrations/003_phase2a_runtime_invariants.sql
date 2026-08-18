BEGIN;

-- 稳定 Seat 只能被同一 integration client 开通一次；重试必须复用原 operation_id 记录。
CREATE UNIQUE INDEX uq_integration_operations_current_provision_seat_target
    ON integration_operations(integration_client_id, target_external_id)
    WHERE migration_state = 'CURRENT'
      AND operation_type = 'PROVISION'
      AND target_type = 'SEAT';

COMMENT ON INDEX uq_integration_operations_current_provision_seat_target IS
    '禁止不同 operation_id 对同一 CURRENT Seat 重复开通或以新操作回退其生命周期';

COMMIT;
