-- Verified Zoom webhooks may update only the live room matched by the
-- HMAC-verified meeting id. The application sets these values transaction-locally.
CREATE POLICY live_room_webhook_state_update_policy ON live_rooms
    FOR UPDATE
    USING (
        current_setting('app.webhook_lookup_verified', true) = 'true'
        AND meeting_external_id = current_setting('app.webhook_lookup_meeting_id', true)
    )
    WITH CHECK (
        current_setting('app.webhook_lookup_verified', true) = 'true'
        AND meeting_external_id = current_setting('app.webhook_lookup_meeting_id', true)
    );
