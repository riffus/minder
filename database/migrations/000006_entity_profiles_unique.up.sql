-- We may only have a single entity profile per profile+entity combination,
-- so we can use a unique index to enforce this.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS entity_profiles_unique ON
entity_profiles (entity, profile_id);