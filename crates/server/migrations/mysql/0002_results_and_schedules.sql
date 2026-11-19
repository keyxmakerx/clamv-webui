-- Jobs record how many result lines were left out of the stored lists; schedules get a time zone; max_streams was never used.
-- TEXT is 64 KB on MySQL/MariaDB; large scan results and reports need MEDIUMTEXT (16 MB).
ALTER TABLE scan_jobs ADD COLUMN results_omitted BIGINT NOT NULL DEFAULT 0;
ALTER TABLE scan_jobs MODIFY detections_json MEDIUMTEXT, MODIFY errors_json MEDIUMTEXT, MODIFY error_message MEDIUMTEXT;
ALTER TABLE integrity_reports MODIFY findings_json MEDIUMTEXT NOT NULL;
ALTER TABLE firewall_plans MODIFY rules_json MEDIUMTEXT NOT NULL;
ALTER TABLE scan_schedules ADD COLUMN time_zone VARCHAR(64);
ALTER TABLE scan_schedules DROP COLUMN max_streams;
