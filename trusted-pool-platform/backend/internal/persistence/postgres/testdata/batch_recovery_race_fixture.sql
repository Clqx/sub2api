INSERT INTO members (id,external_id,sub2api_user_id,display_name,status) VALUES
('10000000-0000-0000-0000-000000000002','batch-recovery-from-member',1001,'From Member','ACTIVE'),
('10000000-0000-0000-0000-000000000003','batch-recovery-target-member',1002,'Target Member','ACTIVE');
INSERT INTO pools (id,external_id,name,status,member_limit,membership_epoch,credential_epoch_floor)
VALUES ('10000000-0000-0000-0000-000000000001','batch-recovery-race-pool',
'Batch Recovery Race Pool','ACTIVE',2,1,1);
INSERT INTO seats (id,external_id,pool_id,seat_no,status,owner_member_id,assignment_epoch,
sub2api_principal_id,sub2api_subscription_id,sub2api_api_key_id,active_api_key_version,frozen_at)
VALUES ('10000000-0000-0000-0000-000000000004','batch-recovery-race-seat',
'10000000-0000-0000-0000-000000000001',1,'FROZEN',
'10000000-0000-0000-0000-000000000002',1,101,201,301,1,CURRENT_TIMESTAMP);
INSERT INTO seat_assignments (seat_id,pool_id,member_id,assignment_type,status,
assignment_epoch,starts_at) VALUES
('10000000-0000-0000-0000-000000000004','10000000-0000-0000-0000-000000000001',
'10000000-0000-0000-0000-000000000002','PERMANENT','ACTIVE',1,CURRENT_TIMESTAMP);
INSERT INTO integration_operations (id,integration_client_id,operation_id,operation_type,
target_type,target_id,target_external_id,migration_state,request_hash,request_snapshot,status,
response_snapshot,completed_at,fencing_token,attempt_count)
VALUES ('20000000-0000-0000-0000-000000000009','batch-recovery-fixture',
'batch-recovery-freeze','SUSPEND','SEAT','10000000-0000-0000-0000-000000000004',
'batch-recovery-race-seat','CURRENT',decode(repeat('19',32),'hex'),'{"fixture":"freeze"}',
'SUCCEEDED','{"status":"frozen"}',CURRENT_TIMESTAMP,1,1);
INSERT INTO suspension_cases (id,seat_id,operation_id,status,reason_code,evidence_refs,
expected_assignment_epoch,blocked_at,frozen_at,freeze_snapshot,integration_operation_id,
migration_state,current_concurrency,pending_settlements,version)
VALUES ('10000000-0000-0000-0000-000000000010',
'10000000-0000-0000-0000-000000000004','batch-recovery-freeze','FROZEN','RECOVERY',
'[]',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,
jsonb_build_object('in_flight',0,'pending_settlements',0,'captured_at',CURRENT_TIMESTAMP,
'usage',jsonb_build_object('hourly',0,'daily',0,'weekly',0,'monthly',0),
'window_starts',jsonb_build_object('hourly',NULL,'daily',NULL,'weekly',NULL,'monthly',NULL)),
'20000000-0000-0000-0000-000000000009','CURRENT',0,0,3);

INSERT INTO integration_operations (id,integration_client_id,operation_id,operation_type,
target_type,target_id,target_external_id,migration_state,request_hash,request_snapshot,status,
response_snapshot,completed_at,fencing_token,lease_owner,lease_expires_at,attempt_count) VALUES
('20000000-0000-0000-0000-000000000001','batch-recovery-fixture','resource-registration',
'REGISTER_RESOURCE_ACCOUNT','POOL','10000000-0000-0000-0000-000000000001',
'batch-recovery-race-pool','CURRENT',decode(repeat('11',32),'hex'),'{"fixture":"registration"}',
'SUCCEEDED','{"status":"ok"}',CURRENT_TIMESTAMP,0,NULL,NULL,1),
('20000000-0000-0000-0000-000000000002','batch-recovery-fixture','resource-mapping',
'MAP_RESOURCE_ACCOUNT','SEAT','10000000-0000-0000-0000-000000000004',
'batch-recovery-race-seat','CURRENT',decode(repeat('12',32),'hex'),'{"fixture":"mapping"}',
'SUCCEEDED','{"status":"ok"}',CURRENT_TIMESTAMP,0,NULL,NULL,1),
('20000000-0000-0000-0000-000000000003','batch-recovery-race-client',
'batch-recovery-race-ceremony','BOOTSTRAP_RECOVERY_EPOCH','POOL',
'10000000-0000-0000-0000-000000000001','batch-recovery-race-pool','CURRENT',
decode(repeat('13',32),'hex'),'{"fixture":"ceremony"}','RUNNING',NULL,NULL,0,NULL,NULL,1),
('20000000-0000-0000-0000-000000000004','batch-recovery-race-client',
'batch-recovery-race-finalize','FINALIZE_RECOVERY_BOOTSTRAP','POOL',
'10000000-0000-0000-0000-000000000001','batch-recovery-race-pool','CURRENT',
decode(repeat('14',32),'hex'),'{"fixture":"finalization"}','RUNNING',NULL,NULL,11,
'batch-recovery-finalizer',CURRENT_TIMESTAMP+interval '2 minutes',1),
('20000000-0000-0000-0000-000000000005','batch-recovery-race-client',
'batch-recovery-race-prepare-seat','PREPARE_PERMANENT_REPLACEMENT','SEAT',
'10000000-0000-0000-0000-000000000004','batch-recovery-race-seat','CURRENT',
decode(repeat('15',32),'hex'),'{"fixture":"seat-prepare"}','SUCCEEDED',
'{"status":"prepared"}',CURRENT_TIMESTAMP,1,NULL,NULL,1),
('20000000-0000-0000-0000-000000000006','batch-recovery-race-client',
'batch-recovery-race-prepare-pool','PREPARE_RECOVERY_POOL','POOL',
'10000000-0000-0000-0000-000000000001','batch-recovery-race-pool','CURRENT',
decode(repeat('16',32),'hex'),'{"fixture":"pool-prepare"}','SUCCEEDED',
'{"status":"prepared"}',CURRENT_TIMESTAMP,1,NULL,NULL,1),
('20000000-0000-0000-0000-000000000007','batch-recovery-race-client',
'batch-recovery-race-activate-pool','ACTIVATE_RECOVERY_POOL','POOL',
'10000000-0000-0000-0000-000000000001','batch-recovery-race-pool','CURRENT',
decode(repeat('17',32),'hex'),'{"fixture":"pool-activate"}','SUCCEEDED',
'{"status":"activated"}',CURRENT_TIMESTAMP,1,NULL,NULL,1),
('20000000-0000-0000-0000-000000000008','batch-recovery-race-client',
'batch-recovery-race-evidence','VERIFY_RECOVERY_CONTROL','POOL',
'10000000-0000-0000-0000-000000000001','batch-recovery-race-pool','CURRENT',
decode(repeat('18',32),'hex'),'{"fixture":"evidence"}','SUCCEEDED',
'{"status":"verified"}',CURRENT_TIMESTAMP,0,NULL,NULL,1);

INSERT INTO recovery_epoch_plans (id,external_id,integration_operation_id,ceremony_type,
pool_id,from_epoch,to_epoch,status,governance_threshold,recovery_threshold,
required_share_ack_count,expected_member_count,expected_seat_count,expected_resource_count,
expected_control_batch_count,provider_attestation_set_hash,previous_manifest_hash,
from_epoch_status,from_governance_state,bootstrap_attestation_ref,
bootstrap_attestation_digest,bootstrap_attestation_issuer,bootstrap_attestation_key_id,
bootstrap_attestation_signature,bootstrap_attestation_version,ready_at,version)
VALUES ('10000000-0000-0000-0000-000000000005','batch-recovery-race-plan',
'20000000-0000-0000-0000-000000000003','BOOTSTRAP',
'10000000-0000-0000-0000-000000000001',1,2,'READY',1,1,1,1,1,1,4,
decode(repeat('21',32),'hex'),decode(repeat('00',32),'hex'),'ACTIVE','LEGACY_UNVERIFIED',
'bootstrap-attestation',decode(repeat('22',32),'hex'),'fixture-issuer','fixture-key',
decode('23','hex'),1,CURRENT_TIMESTAMP,8);
INSERT INTO membership_epochs (id,pool_id,epoch,status,governance_threshold,recovery_threshold,
activated_at,recovery_plan_id,epoch_recovery_algorithm,epoch_recovery_key_id,
epoch_recovery_key_fingerprint,recovery_governance_state) VALUES
('10000000-0000-0000-0000-000000000006','10000000-0000-0000-0000-000000000001',
1,'ACTIVE',1,1,CURRENT_TIMESTAMP,NULL,NULL,NULL,NULL,'LEGACY_UNVERIFIED'),
('10000000-0000-0000-0000-000000000007','10000000-0000-0000-0000-000000000001',
2,'PREPARING',1,1,NULL,'10000000-0000-0000-0000-000000000005','X25519',
'batch-recovery-key',decode(repeat('33',32),'hex'),'CURRENT');
INSERT INTO membership_epoch_members (epoch_id,member_id,member_role,signing_public_key,
share_index,source_seat_id,migration_state,signing_algorithm,signing_key_id,
signing_key_fingerprint,signing_proof_algorithm,signing_proof,recovery_key_algorithm,
recovery_key_id,recovery_encryption_public_key,recovery_key_fingerprint,
recovery_key_proof_algorithm,recovery_key_proof) VALUES
('10000000-0000-0000-0000-000000000006','10000000-0000-0000-0000-000000000002',
'OWNER',decode('01','hex'),1,NULL,'LEGACY_UNVERIFIED',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),
('10000000-0000-0000-0000-000000000007','10000000-0000-0000-0000-000000000003',
'OWNER',decode('02','hex'),1,'10000000-0000-0000-0000-000000000004','CURRENT','Ed25519',
'signing-key',decode(repeat('34',32),'hex'),'Ed25519',decode('03','hex'),'X25519',
'member-recovery-key',decode('04','hex'),decode(repeat('35',32),'hex'),'Ed25519',decode('05','hex'));

INSERT INTO pool_resource_accounts (id,external_id,pool_id,registration_operation_id,
provider,provider_account_ref,inventory_version,provider_key_ref,attestation_digest,
attestation_signature,status) VALUES
('10000000-0000-0000-0000-000000000009','batch-recovery-account',
'10000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001',
'fixture-provider','batch-recovery-race-account',1,'provider-key',
decode(repeat('41',32),'hex'),decode('42','hex'),'ACTIVE');
INSERT INTO pool_resource_account_seats (resource_account_id,pool_id,seat_id,
mapping_operation_id,inventory_version,status) VALUES
('10000000-0000-0000-0000-000000000009','10000000-0000-0000-0000-000000000001',
'10000000-0000-0000-0000-000000000004','20000000-0000-0000-0000-000000000002',1,'ACTIVE');
INSERT INTO recovery_plan_seats (plan_id,pool_id,from_epoch,to_epoch,seat_id,from_member_id,
to_member_id,expected_assignment_epoch,expected_active_api_key_version,is_replacement,
freeze_suspension_case_id,freeze_operation_id,freeze_snapshot_hash) VALUES
('10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000001',1,2,
'10000000-0000-0000-0000-000000000004','10000000-0000-0000-0000-000000000002',
'10000000-0000-0000-0000-000000000003',1,1,true,
'10000000-0000-0000-0000-000000000010','batch-recovery-freeze',decode(repeat('43',32),'hex'));
INSERT INTO recovery_plan_resource_accounts (plan_id,resource_account_id,pool_id,
account_external_id,provider,provider_account_ref,inventory_version,provider_key_ref,
attestation_digest,provider_binding,control_evidence_external_id,control_attestation_digest,
control_attestation_issuer,control_attestation_key_id,control_attestation_version) VALUES
('10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000009',
'10000000-0000-0000-0000-000000000001','batch-recovery-account','fixture-provider',
'batch-recovery-race-account',1,'provider-key',decode(repeat('41',32),'hex'),
'fixture-binding','batch-recovery-evidence',decode(repeat('44',32),'hex'),
'fixture-issuer','fixture-key',1);
INSERT INTO recovery_plan_account_seats (plan_id,resource_account_id,seat_id,inventory_version)
VALUES ('10000000-0000-0000-0000-000000000005',
'10000000-0000-0000-0000-000000000009','10000000-0000-0000-0000-000000000004',1);

INSERT INTO recovery_root_artifacts (id,external_id,plan_id,provider,provider_key_ref,
root_handle,root_key_version,epoch_recovery_algorithm,epoch_recovery_key_id,
epoch_recovery_key_fingerprint,wrap_domain,wrap_algorithm,vss_algorithm,vss_commitment,
vss_commitment_hash,vss_proof,vss_proof_hash,private_key_commitment,
private_key_commitment_hash,root_commitment_hash,recovery_package_hash,request_intent_hash,
provider_attestation_ref,attestation_digest,attestation_signature,attestation_key_id,migration_state)
VALUES ('10000000-0000-0000-0000-000000000008','batch-recovery-root',
'10000000-0000-0000-0000-000000000005','fixture-provider','provider-key','root-handle',
'root-v1','X25519','batch-recovery-key',decode(repeat('33',32),'hex'),
'recovery/wrap/v1','AES-KWP','FROST-v1',decode('51','hex'),digest(decode('51','hex'),'sha256'),
decode('52','hex'),digest(decode('52','hex'),'sha256'),decode('53','hex'),
digest(decode('53','hex'),'sha256'),decode(repeat('54',32),'hex'),
decode(repeat('55',32),'hex'),decode(repeat('56',32),'hex'),'provider-attestation',
decode(repeat('57',32),'hex'),decode('58','hex'),'provider-key','CURRENT');
INSERT INTO manifests (id,epoch_id,protocol_version,canonical_payload,manifest_hash,
platform_signature,status,external_id,recovery_plan_id,root_artifact_id,migration_state,
canonical_bytes,previous_manifest_hash,batch_set_hash,recovery_package_hash,
provider_attestation_digest,platform_algorithm,platform_key_ref,platform_verified_at)
VALUES ('10000000-0000-0000-0000-000000000011',
'10000000-0000-0000-0000-000000000007','trusted-pool/recovery-governance/v1','{}',
digest(convert_to('{}','UTF8'),'sha256'),decode('61','hex'),'DRAFT','batch-recovery-manifest',
'10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000008',
'CURRENT',convert_to('{}','UTF8'),decode(repeat('00',32),'hex'),decode(repeat('62',32),'hex'),
decode(repeat('55',32),'hex'),decode(repeat('57',32),'hex'),'Ed25519','platform-key',
CURRENT_TIMESTAMP);

WITH kinds(kind,n) AS (VALUES ('LOGIN',1),('MFA',2),('RECOVERY',3),('OWNERSHIP',4))
INSERT INTO integration_operations (id,integration_client_id,operation_id,operation_type,
target_type,target_id,target_external_id,migration_state,request_hash,request_snapshot,status,
response_snapshot,completed_at)
SELECT ('31000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,'batch-recovery-fixture',
'batch-recovery-seal-'||lower(kind),'SEAL_CREDENTIAL_BATCH','CREDENTIAL_BATCH',
('30000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,
'batch-recovery-from-'||lower(kind),'CURRENT',decode(repeat('81',32),'hex'),
jsonb_build_object('version',1,'operation_id','batch-recovery-seal-'||lower(kind),
'batch_id','batch-recovery-from-'||lower(kind),'pool_id','batch-recovery-race-pool',
'account_ref','batch-recovery-race-account','batch_type',kind,'batch_version',1,
'membership_epoch',1,'content_fingerprint',repeat('82',32)),'SUCCEEDED',
jsonb_build_object('version',1,'operation_id','batch-recovery-seal-'||lower(kind),
'batch_id','batch-recovery-from-'||lower(kind),'pool_id','batch-recovery-race-pool',
'account_ref','batch-recovery-race-account','batch_type',kind,'batch_version',1,
'membership_epoch',1,'state','SEALED','record_version',2,
'content_fingerprint',repeat('82',32),'aad_hash',repeat('83',32),
'sealed_at',CURRENT_TIMESTAMP,'activated_at',NULL,'retired_at',NULL),CURRENT_TIMESTAMP FROM kinds;

WITH kinds(kind,n) AS (VALUES ('LOGIN',1),('MFA',2),('RECOVERY',3),('OWNERSHIP',4))
INSERT INTO credential_batches (id,pool_id,membership_epoch,resource_account_ref,batch_type,
batch_version,status,encryption_algorithm,ciphertext,nonce,aad_hash,content_hash,
encrypted_dek_kms,encrypted_dek_recovery,activated_at,external_id,migration_state,
seal_integration_operation_id,aad_version,kms_wrap_algorithm,kms_key_ref,kms_wrapper_domain,
recovery_wrap_algorithm,recovery_key_ref,recovery_wrapper_domain,recovery_binding_hash,
sealed_at,version)
SELECT ('30000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,
'10000000-0000-0000-0000-000000000001',1,'batch-recovery-race-account',kind,1,
'ACTIVE','AES-256-GCM',decode('84','hex'),decode(repeat('85',12),'hex'),
decode(repeat('83',32),'hex'),decode(repeat('82',32),'hex'),decode('86','hex'),
decode('87','hex'),CURRENT_TIMESTAMP,'batch-recovery-from-'||lower(kind),'CURRENT',
('31000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,1,'AES-KWP','kms://batch',
'batch/online/v1','AES-KWP','recovery://batch','batch/recovery/v1',
credential_recovery_binding_hash('batch/recovery/v1','AES-KWP','recovery://batch',
decode(repeat('83',32),'hex'),decode('87','hex')),CURRENT_TIMESTAMP,3 FROM kinds;

WITH kinds(kind,n) AS (VALUES ('LOGIN',1),('MFA',2),('RECOVERY',3),('OWNERSHIP',4))
INSERT INTO integration_operations (id,integration_client_id,operation_id,operation_type,
target_type,target_id,target_external_id,migration_state,request_hash,request_snapshot,status,
response_snapshot,completed_at)
SELECT ('32000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,'batch-recovery-fixture',
'batch-recovery-activate-'||lower(kind),'ACTIVATE_CREDENTIAL_BATCH','CREDENTIAL_BATCH',
('30000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,
'batch-recovery-from-'||lower(kind),'CURRENT',decode(repeat('88',32),'hex'),
jsonb_build_object('version',1,'operation_id','batch-recovery-activate-'||lower(kind),
'batch_id','batch-recovery-from-'||lower(kind),'action','ACTIVATE','expected_record_version',2),
'SUCCEEDED',jsonb_build_object('version',1,'operation_id','batch-recovery-activate-'||lower(kind),
'batch_id','batch-recovery-from-'||lower(kind),'pool_id','batch-recovery-race-pool',
'account_ref','batch-recovery-race-account','batch_type',kind,'batch_version',1,
'membership_epoch',1,'state','ACTIVE','record_version',3,
'content_fingerprint',repeat('82',32),'aad_hash',repeat('83',32),
'sealed_at',CURRENT_TIMESTAMP,'activated_at',CURRENT_TIMESTAMP,'retired_at',NULL),
CURRENT_TIMESTAMP FROM kinds;
WITH kinds(kind,n) AS (VALUES ('LOGIN',1),('MFA',2),('RECOVERY',3),('OWNERSHIP',4))
INSERT INTO credential_batch_transitions (integration_operation_id,credential_batch_id,
transition_type,from_status,to_status,expected_batch_version,resulting_batch_version,occurred_at)
SELECT ('32000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,
('30000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,
'ACTIVATE','SEALED','ACTIVE',2,3,CURRENT_TIMESTAMP FROM kinds;
WITH kinds(kind,n) AS (VALUES ('LOGIN',1),('MFA',2),('RECOVERY',3),('OWNERSHIP',4))
INSERT INTO recovery_plan_batch_bindings (plan_id,resource_account_id,epoch_role,batch_type,
credential_batch_id,ciphertext_hash)
SELECT '10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000009',
'FROM',kind,('30000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,
decode(repeat('89',32),'hex') FROM kinds;

WITH kinds(kind,n) AS (VALUES ('LOGIN',1),('MFA',2),('RECOVERY',3),('OWNERSHIP',4))
INSERT INTO credential_batches (id,pool_id,membership_epoch,resource_account_ref,batch_type,
batch_version,status,encryption_algorithm,ciphertext,nonce,aad_hash,content_hash,
encrypted_dek_kms,encrypted_dek_recovery,external_id,migration_state,seal_integration_operation_id,
aad_version,kms_wrap_algorithm,kms_key_ref,kms_wrapper_domain,recovery_wrap_algorithm,
recovery_key_ref,recovery_wrapper_domain,recovery_binding_hash,sealed_at,version,
recovery_plan_id,recovery_root_artifact_id,resource_account_id,recovery_key_fingerprint,
recovery_key_version,recovery_wrap_attestation_digest,recovery_wrap_attestation_signature)
SELECT ('40000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,
'10000000-0000-0000-0000-000000000001',2,'batch-recovery-race-account',kind,2,
'STAGED','AES-256-GCM',decode('91','hex'),decode(repeat('92',12),'hex'),
decode(repeat('93',32),'hex'),decode(repeat('94',32),'hex'),decode('95','hex'),
decode('96','hex'),'batch-recovery-to-'||lower(kind),'CURRENT',NULL,1,'AES-KWP',
'kms://batch','batch/online/v1','AES-KWP','batch-recovery-key','recovery/wrap/v1',
credential_recovery_binding_hash('recovery/wrap/v1','AES-KWP','batch-recovery-key',
decode(repeat('93',32),'hex'),decode('96','hex')),CURRENT_TIMESTAMP,1,
'10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000008',
'10000000-0000-0000-0000-000000000009',decode(repeat('33',32),'hex'),'root-v1',
decode(repeat('97',32),'hex'),decode('98','hex') FROM kinds;
WITH kinds(kind,n) AS (VALUES ('LOGIN',1),('MFA',2),('RECOVERY',3),('OWNERSHIP',4))
INSERT INTO recovery_plan_batch_bindings (plan_id,resource_account_id,epoch_role,batch_type,
credential_batch_id,ciphertext_hash,recovery_wrap_hash)
SELECT '10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000009',
'TO',kind,('40000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,
decode(repeat('99',32),'hex'),decode(repeat('9a',32),'hex') FROM kinds;

INSERT INTO permanent_replacement_cases (external_id,integration_operation_id,plan_id,status,version)
VALUES ('batch-recovery-race-case','20000000-0000-0000-0000-000000000004',
'10000000-0000-0000-0000-000000000005','READY_TO_COMMIT',4);
INSERT INTO recovery_pool_preparation_attempts (plan_id,integration_operation_id,
intent_set_hash,status,version) VALUES
('10000000-0000-0000-0000-000000000005','20000000-0000-0000-0000-000000000006',
decode(repeat('71',32),'hex'),'PREPARED',2);
INSERT INTO recovery_pool_activation_attempts (id,plan_id,integration_operation_id,
prepared_set_hash,status,provider_attestation_ref,provider_attestation_digest,
provider_attestation_issuer,provider_attestation_key_id,provider_attestation_version,
provider_attestation_signature,old_credential_set_invalidated,
credential_fingerprint_gate_enforced,authorization_cache_invalidated,
authorization_cache_durable_outbox,auth_cache_minimum_events,activated_at,version)
VALUES ('10000000-0000-0000-0000-000000000012',
'10000000-0000-0000-0000-000000000005','20000000-0000-0000-0000-000000000007',
decode(repeat('72',32),'hex'),'ACTIVATED','activation-attestation',
decode(repeat('73',32),'hex'),'fixture-issuer','fixture-key',1,decode('74','hex'),
true,true,true,true,2,CURRENT_TIMESTAMP,2);
INSERT INTO recovery_pool_activation_seats (activation_attempt_id,plan_id,seat_id,
target_member_id,prepared_reference,principal_user_id,subscription_id,api_key_id,
api_key_version,credential_fingerprint,current_concurrency,pending_settlements)
VALUES ('10000000-0000-0000-0000-000000000012',
'10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000004',
'10000000-0000-0000-0000-000000000003','prepared-seat-reference',101,201,301,2,
decode(repeat('75',32),'hex'),0,0);
INSERT INTO recovery_seat_rotation_progress (plan_id,seat_id,derived_operation_id,status,
principal_user_id,subscription_id,api_key_id,api_key_version,credential_fingerprint,
envelope_algorithm,envelope_key_ref,envelope_ciphertext,envelope_nonce,envelope_aad_hash,
wrapped_dek_kms,attempt_count,prepared_reference,provider_result_digest)
VALUES ('10000000-0000-0000-0000-000000000005',
'10000000-0000-0000-0000-000000000004','20000000-0000-0000-0000-000000000005',
'ACTIVATED',101,201,301,2,decode(repeat('75',32),'hex'),'AES-256-GCM','kms://replacement',
decode('76','hex'),decode(repeat('77',12),'hex'),decode(repeat('78',32),'hex'),
decode('79','hex'),1,'prepared-seat-reference',decode(repeat('7a',32),'hex'));
INSERT INTO recovery_control_evidence (external_id,integration_operation_id,plan_id,
resource_account_id,provider_attestation_ref,provider_attestation_digest,
provider_attestation_issuer,provider_attestation_key_id,provider_attestation_version,
ceremony_type,attestation_purpose,status)
VALUES ('batch-recovery-evidence','20000000-0000-0000-0000-000000000008',
'10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000009',
'control-attestation',decode(repeat('44',32),'hex'),'fixture-issuer','fixture-key',1,
'BOOTSTRAP','BOOTSTRAP_GENESIS','VERIFIED');
