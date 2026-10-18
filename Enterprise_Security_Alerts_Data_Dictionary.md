# Enterprise Security Alerts Classification: Dataset Dictionary

## Dataset overview

**File:** `Enterprise_Security_Alerts_Classification.csv`  
**Rows:** 52,000  
**Columns:** 37, including the target  
**Observation period:** January 2024 to December 2025  
**Task:** Binary classification of an alert at the moment it is raised.

`confirmed_incident` is the target, with `1` indicating a confirmed incident and `0` indicating an alert not confirmed as an incident. The positive class is relatively rare, so selecting and evaluating a classifier using overall accuracy alone is inappropriate.

The CSV is supplied as an educational case-study dataset. It should not be represented as an operational record of a real company.

## Variable reference

| Column | Meaning | Information availability |
|---|---|---|
| `alert_id` | Unique alert record identifier | At alert creation. Identifier, not a meaningful predictor. |
| `alert_created_at` | Timestamp when the alert was raised | At alert creation. Used for chronological splitting and suitable time features. |
| `tenant_id` | Organization or tenant identifier | At alert creation. Audit potential memorization and generalization effects. |
| `host_id` | Monitored endpoint or system identifier | At alert creation. Audit repeated-entity effects. |
| `identity_id` | User or service-identity identifier | At alert creation. Audit repeated-entity effects. |
| `deployment_environment` | Cloud, on-premises, or hybrid | At alert creation. |
| `site_region` | Geographic infrastructure region | At alert creation. |
| `device_type` | Type of monitored device | At alert creation, sometimes unavailable. |
| `operating_system` | Endpoint or server operating-system family | At alert creation. |
| `detection_family` | Class of detector that generated the alert | At alert creation. |
| `log_source` | Source security-monitoring system | At alert creation. |
| `account_privilege` | Account access level | At alert creation. |
| `asset_criticality` | Asset business importance | At alert creation. |
| `detector_severity` | Alert severity assigned by the original detector | At alert creation; **not** the classification target. |
| `source_ip_region` | Broad geographic relation of the source IP | At alert creation, sometimes unavailable. |
| `mfa_enabled` | Whether multi-factor authentication is configured (0/1) | At alert creation. |
| `new_device_last_30d` | Newly observed device indicator (0/1) | At alert creation. |
| `off_hours_activity` | Off-hours activity indicator (0/1) | At alert creation. |
| `external_ip_reputation` | Risk-oriented IP reputation indicator (0 to 100; higher implies greater suspicion) | At alert creation, sometimes unavailable. |
| `endpoint_risk_score` | Endpoint risk telemetry score (0 to 100) | At alert creation, sometimes unavailable. |
| `failed_auth_attempts_24h` | Failed authentications during previous 24 hours | At alert creation, sometimes unavailable. |
| `successful_auths_24h` | Successful authentications during previous 24 hours | At alert creation. |
| `distinct_source_ips_24h` | Number of distinct source IPs in the previous day | At alert creation. |
| `external_connections_1h` | Outbound connection count in the preceding hour | At alert creation. |
| `outbound_mb_1h` | Megabytes sent externally in preceding hour | At alert creation. |
| `inbound_mb_1h` | Megabytes received in preceding hour | At alert creation. |
| `unusual_destination_port` | Unusual destination port indicator (0/1) | At alert creation. |
| `geo_velocity_kmh` | Estimated geographic-travel velocity between authentication signals | At alert creation, sometimes unavailable. |
| `days_since_patch` | Days since the last recorded patch | At alert creation, sometimes unavailable. |
| `account_age_days` | Age of the associated account in days | At alert creation. |
| `prior_alerts_90d` | Historical number of alerts for the monitored context | At alert creation. |
| `alert_burst_count_1h` | Number of associated alerts in recent activity window | At alert creation. |
| `case_disposition` | Disposition recorded by a subsequent analyst investigation | **After** alert creation; post-investigation field. |
| `remediation_action` | Remediation action taken during or after investigation | **After** alert creation; post-investigation field. |
| `forensic_score_after_review` | Score resulting from post-alert forensic analysis | **After** alert creation; post-investigation field. |
| `case_closed_at` | Time when a case investigation was closed | **After** alert creation; post-investigation field. |
| `confirmed_incident` | Whether the alert was confirmed as an incident (0/1) | Outcome/label; never a predictor. |

## Assessment protocol

Use the timestamps to separate **2024 for training**, **January to June 2025 for validation**, and **July to December 2025 for final testing**. Fit imputers, encoders, scalers, and feature selection within the training fold. Use the validation period to choose models, imbalance strategies, and any decision threshold. Evaluate the final test period once.

Review which fields existed at alert creation. Fields that only exist after an analyst investigation are not legitimate prediction-time inputs. Identifiers may be retained for grouping, auditing, or evaluation, but require explicit justification before being used as features.

Evaluate a majority-class baseline, report class prevalence for every split, and use minority-class precision, recall, F1, PR-AUC, and confusion matrices. Compare an imbalance-aware approach against a non-resampled benchmark. If resampling is used, apply it only to the training portion within the modeling pipeline, never to validation or test data.

Avoid interpreting results as verified operational performance outside this educational case study.