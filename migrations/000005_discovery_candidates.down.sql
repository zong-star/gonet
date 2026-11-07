-- Deliberately retain candidate history on rollback. Older binaries ignore
-- this additive table; dropping it would discard pending discovery evidence.
SELECT 1;
