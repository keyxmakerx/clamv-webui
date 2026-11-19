-- Jobs record how many result lines were left out of the stored lists; schedules get a time zone; max_streams was never used.
ALTER TABLE scan_jobs ADD COLUMN results_omitted BIGINT NOT NULL DEFAULT 0;
ALTER TABLE scan_schedules ADD COLUMN time_zone VARCHAR(64);
ALTER TABLE scan_schedules DROP COLUMN max_streams;
