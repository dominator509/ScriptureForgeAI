-- One canonical vector-bearing row per tenant/reference.
-- This supports idempotent scripture ingestion without weakening tenant RLS.
CREATE UNIQUE INDEX idx_scripture_texts_org_reference_unique
    ON scripture_texts (organization_id, book, chapter, verse);
