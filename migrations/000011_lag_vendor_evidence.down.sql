-- Do not erase vendor evidence to enable an older binary. Downgrade requires
-- an explicit, reviewed retention/export decision and a compatible reader.
DO $$ BEGIN
    RAISE EXCEPTION 'Use a forward-compatible application rollback; LAG evidence downgrade is intentionally disabled';
END $$;
