-- SPDX-License-Identifier: GPL-3.0-only
-- Records the cloud refused for good (validation): kept locally, no longer retried, reason shown in Settings.
ALTER TABLE outbox ADD COLUMN rejected TEXT;
