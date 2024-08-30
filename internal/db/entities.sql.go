// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: entities.sql

package db

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const createEntity = `-- name: CreateEntity :one

INSERT INTO entity_instances (
    entity_type,
    name,
    project_id,
    provider_id,
    originated_from
) VALUES ($1, $2, $3, $4, $5)
RETURNING id, entity_type, name, project_id, provider_id, created_at, originated_from
`

type CreateEntityParams struct {
	EntityType     Entities      `json:"entity_type"`
	Name           string        `json:"name"`
	ProjectID      uuid.UUID     `json:"project_id"`
	ProviderID     uuid.UUID     `json:"provider_id"`
	OriginatedFrom uuid.NullUUID `json:"originated_from"`
}

// CreateEntity adds an entry to the entity_instances table so it can be tracked by Minder.
func (q *Queries) CreateEntity(ctx context.Context, arg CreateEntityParams) (EntityInstance, error) {
	row := q.db.QueryRowContext(ctx, createEntity,
		arg.EntityType,
		arg.Name,
		arg.ProjectID,
		arg.ProviderID,
		arg.OriginatedFrom,
	)
	var i EntityInstance
	err := row.Scan(
		&i.ID,
		&i.EntityType,
		&i.Name,
		&i.ProjectID,
		&i.ProviderID,
		&i.CreatedAt,
		&i.OriginatedFrom,
	)
	return i, err
}

const createEntityWithID = `-- name: CreateEntityWithID :one

INSERT INTO entity_instances (
    id,
    entity_type,
    name,
    project_id,
    provider_id,
    originated_from
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, entity_type, name, project_id, provider_id, created_at, originated_from
`

type CreateEntityWithIDParams struct {
	ID             uuid.UUID     `json:"id"`
	EntityType     Entities      `json:"entity_type"`
	Name           string        `json:"name"`
	ProjectID      uuid.UUID     `json:"project_id"`
	ProviderID     uuid.UUID     `json:"provider_id"`
	OriginatedFrom uuid.NullUUID `json:"originated_from"`
}

// CreateEntityWithID adds an entry to the entities table with a specific ID so it can be tracked by Minder.
func (q *Queries) CreateEntityWithID(ctx context.Context, arg CreateEntityWithIDParams) (EntityInstance, error) {
	row := q.db.QueryRowContext(ctx, createEntityWithID,
		arg.ID,
		arg.EntityType,
		arg.Name,
		arg.ProjectID,
		arg.ProviderID,
		arg.OriginatedFrom,
	)
	var i EntityInstance
	err := row.Scan(
		&i.ID,
		&i.EntityType,
		&i.Name,
		&i.ProjectID,
		&i.ProviderID,
		&i.CreatedAt,
		&i.OriginatedFrom,
	)
	return i, err
}

const createOrEnsureEntityByID = `-- name: CreateOrEnsureEntityByID :one

INSERT INTO entity_instances (
    id,
    entity_type,
    name,
    project_id,
    provider_id,
    originated_from
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (id) DO UPDATE
SET
    id = entity_instances.id  -- This is a "noop" update to ensure the RETURNING clause works
RETURNING id, entity_type, name, project_id, provider_id, created_at, originated_from
`

type CreateOrEnsureEntityByIDParams struct {
	ID             uuid.UUID     `json:"id"`
	EntityType     Entities      `json:"entity_type"`
	Name           string        `json:"name"`
	ProjectID      uuid.UUID     `json:"project_id"`
	ProviderID     uuid.UUID     `json:"provider_id"`
	OriginatedFrom uuid.NullUUID `json:"originated_from"`
}

// CreateOrEnsureEntityByID adds an entry to the entity_instances table if it does not exist, or returns the existing entry.
func (q *Queries) CreateOrEnsureEntityByID(ctx context.Context, arg CreateOrEnsureEntityByIDParams) (EntityInstance, error) {
	row := q.db.QueryRowContext(ctx, createOrEnsureEntityByID,
		arg.ID,
		arg.EntityType,
		arg.Name,
		arg.ProjectID,
		arg.ProviderID,
		arg.OriginatedFrom,
	)
	var i EntityInstance
	err := row.Scan(
		&i.ID,
		&i.EntityType,
		&i.Name,
		&i.ProjectID,
		&i.ProviderID,
		&i.CreatedAt,
		&i.OriginatedFrom,
	)
	return i, err
}

const deleteAllPropertiesForEntity = `-- name: DeleteAllPropertiesForEntity :exec
DELETE FROM properties
WHERE entity_id = $1
`

func (q *Queries) DeleteAllPropertiesForEntity(ctx context.Context, entityID uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteAllPropertiesForEntity, entityID)
	return err
}

const deleteEntity = `-- name: DeleteEntity :exec

DELETE FROM entity_instances
WHERE id = $1 AND project_id = $2
`

type DeleteEntityParams struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"project_id"`
}

// DeleteEntity removes an entity from the entity_instances table for a project.
func (q *Queries) DeleteEntity(ctx context.Context, arg DeleteEntityParams) error {
	_, err := q.db.ExecContext(ctx, deleteEntity, arg.ID, arg.ProjectID)
	return err
}

const deleteEntityByName = `-- name: DeleteEntityByName :exec

DELETE FROM entity_instances
WHERE name = $2 AND project_id = $1
`

type DeleteEntityByNameParams struct {
	ProjectID uuid.UUID `json:"project_id"`
	Name      string    `json:"name"`
}

// DeleteEntityByName removes an entity from the entity_instances table for a project.
func (q *Queries) DeleteEntityByName(ctx context.Context, arg DeleteEntityByNameParams) error {
	_, err := q.db.ExecContext(ctx, deleteEntityByName, arg.ProjectID, arg.Name)
	return err
}

const deleteProperty = `-- name: DeleteProperty :exec
DELETE FROM properties
WHERE entity_id = $1 AND key = $2
`

type DeletePropertyParams struct {
	EntityID uuid.UUID `json:"entity_id"`
	Key      string    `json:"key"`
}

func (q *Queries) DeleteProperty(ctx context.Context, arg DeletePropertyParams) error {
	_, err := q.db.ExecContext(ctx, deleteProperty, arg.EntityID, arg.Key)
	return err
}

const getAllPropertiesForEntity = `-- name: GetAllPropertiesForEntity :many
SELECT id, entity_id, key, value, updated_at FROM properties
WHERE entity_id = $1
`

func (q *Queries) GetAllPropertiesForEntity(ctx context.Context, entityID uuid.UUID) ([]Property, error) {
	rows, err := q.db.QueryContext(ctx, getAllPropertiesForEntity, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Property{}
	for rows.Next() {
		var i Property
		if err := rows.Scan(
			&i.ID,
			&i.EntityID,
			&i.Key,
			&i.Value,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEntitiesByType = `-- name: GetEntitiesByType :many

SELECT id, entity_type, name, project_id, provider_id, created_at, originated_from FROM entity_instances
WHERE entity_instances.entity_type = $1 AND entity_instances.project_id = ANY($2::uuid[])
`

type GetEntitiesByTypeParams struct {
	EntityType Entities    `json:"entity_type"`
	Projects   []uuid.UUID `json:"projects"`
}

// GetEntitiesByType retrieves all entities of a given type for a project or hierarchy of projects.
// this is how one would get all repositories, artifacts, etc.
func (q *Queries) GetEntitiesByType(ctx context.Context, arg GetEntitiesByTypeParams) ([]EntityInstance, error) {
	rows, err := q.db.QueryContext(ctx, getEntitiesByType, arg.EntityType, pq.Array(arg.Projects))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []EntityInstance{}
	for rows.Next() {
		var i EntityInstance
		if err := rows.Scan(
			&i.ID,
			&i.EntityType,
			&i.Name,
			&i.ProjectID,
			&i.ProviderID,
			&i.CreatedAt,
			&i.OriginatedFrom,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEntityByID = `-- name: GetEntityByID :one

SELECT id, entity_type, name, project_id, provider_id, created_at, originated_from FROM entity_instances
WHERE entity_instances.id = $1 AND entity_instances.project_id = ANY($2::uuid[])
LIMIT 1
`

type GetEntityByIDParams struct {
	ID       uuid.UUID   `json:"id"`
	Projects []uuid.UUID `json:"projects"`
}

// GetEntityByID retrieves an entity by its ID for a project or hierarchy of projects.
func (q *Queries) GetEntityByID(ctx context.Context, arg GetEntityByIDParams) (EntityInstance, error) {
	row := q.db.QueryRowContext(ctx, getEntityByID, arg.ID, pq.Array(arg.Projects))
	var i EntityInstance
	err := row.Scan(
		&i.ID,
		&i.EntityType,
		&i.Name,
		&i.ProjectID,
		&i.ProviderID,
		&i.CreatedAt,
		&i.OriginatedFrom,
	)
	return i, err
}

const getEntityByName = `-- name: GetEntityByName :one
SELECT id, entity_type, name, project_id, provider_id, created_at, originated_from FROM entity_instances
WHERE entity_instances.name = $3 AND entity_instances.project_id = $1 AND entity_instances.entity_type = $2
LIMIT 1
`

type GetEntityByNameParams struct {
	ProjectID  uuid.UUID `json:"project_id"`
	EntityType Entities  `json:"entity_type"`
	Name       string    `json:"name"`
}

// GetEntityByName retrieves an entity by its name for a project or hierarchy of projects.
func (q *Queries) GetEntityByName(ctx context.Context, arg GetEntityByNameParams) (EntityInstance, error) {
	row := q.db.QueryRowContext(ctx, getEntityByName, arg.ProjectID, arg.EntityType, arg.Name)
	var i EntityInstance
	err := row.Scan(
		&i.ID,
		&i.EntityType,
		&i.Name,
		&i.ProjectID,
		&i.ProviderID,
		&i.CreatedAt,
		&i.OriginatedFrom,
	)
	return i, err
}

const getProperty = `-- name: GetProperty :one
SELECT id, entity_id, key, value, updated_at FROM properties
WHERE entity_id = $1 AND key = $2
`

type GetPropertyParams struct {
	EntityID uuid.UUID `json:"entity_id"`
	Key      string    `json:"key"`
}

func (q *Queries) GetProperty(ctx context.Context, arg GetPropertyParams) (Property, error) {
	row := q.db.QueryRowContext(ctx, getProperty, arg.EntityID, arg.Key)
	var i Property
	err := row.Scan(
		&i.ID,
		&i.EntityID,
		&i.Key,
		&i.Value,
		&i.UpdatedAt,
	)
	return i, err
}

const getTypedEntitiesByProperty = `-- name: GetTypedEntitiesByProperty :many
SELECT ei.id, ei.entity_type, ei.name, ei.project_id, ei.provider_id, ei.created_at, ei.originated_from
FROM entity_instances ei
         JOIN properties p ON ei.id = p.entity_id
WHERE ei.entity_type = $1
  AND ($2::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR ei.project_id = $2)
  AND p.key = $3
  AND p.value @> $4::jsonb
`

type GetTypedEntitiesByPropertyParams struct {
	EntityType Entities        `json:"entity_type"`
	ProjectID  uuid.UUID       `json:"project_id"`
	Key        string          `json:"key"`
	Value      json.RawMessage `json:"value"`
}

func (q *Queries) GetTypedEntitiesByProperty(ctx context.Context, arg GetTypedEntitiesByPropertyParams) ([]EntityInstance, error) {
	rows, err := q.db.QueryContext(ctx, getTypedEntitiesByProperty,
		arg.EntityType,
		arg.ProjectID,
		arg.Key,
		arg.Value,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []EntityInstance{}
	for rows.Next() {
		var i EntityInstance
		if err := rows.Scan(
			&i.ID,
			&i.EntityType,
			&i.Name,
			&i.ProjectID,
			&i.ProviderID,
			&i.CreatedAt,
			&i.OriginatedFrom,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const upsertProperty = `-- name: UpsertProperty :one
INSERT INTO properties (
    entity_id,
    key,
    value,
    updated_at
) VALUES ($1, $2, $3, NOW())
ON CONFLICT (entity_id, key) DO UPDATE
    SET
        value = $4,
        updated_at = NOW()
RETURNING id, entity_id, key, value, updated_at
`

type UpsertPropertyParams struct {
	EntityID uuid.UUID       `json:"entity_id"`
	Key      string          `json:"key"`
	Value    json.RawMessage `json:"value"`
}

func (q *Queries) UpsertProperty(ctx context.Context, arg UpsertPropertyParams) (Property, error) {
	row := q.db.QueryRowContext(ctx, upsertProperty,
		arg.EntityID,
		arg.Key,
		arg.Value,
		arg.Value,
	)
	var i Property
	err := row.Scan(
		&i.ID,
		&i.EntityID,
		&i.Key,
		&i.Value,
		&i.UpdatedAt,
	)
	return i, err
}