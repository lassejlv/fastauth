-- The app's own table. It references fastauth's tables like any other foreign key.
CREATE TABLE project (
    id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    organization_id text NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    name text NOT NULL,
    created_by text NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX project_organization_id_idx ON project (organization_id);
