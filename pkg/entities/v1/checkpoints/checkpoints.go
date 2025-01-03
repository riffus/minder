// SPDX-FileCopyrightText: Copyright 2024 The Minder Authors
// SPDX-License-Identifier: Apache-2.0

// Package checkpoints contains logic relating to checkpoint management for entities
package checkpoints

import (
	"encoding/json"
	"time"
)

// V1 is the version string for the v1 format.
const V1 = "v1"

// CheckpointEnvelopeV1 is the top-level structure for a checkpoint
// in the v1 format.
type CheckpointEnvelopeV1 struct {
	Version    string       `json:"version" yaml:"version"`
	Checkpoint CheckpointV1 `json:"checkpoint" yaml:"checkpoint"`
}

// CheckpointV1 is the structure for a checkpoint in the v1 format.
type CheckpointV1 struct {
	// Timestamp is the time that the checkpoint was verified.
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`

	// CommitHash is the hash of the commit that the checkpoint is for.
	CommitHash *string `json:"commitHash,omitempty" yaml:"commitHash,omitempty"`

	// Branch is the branch of the commit that the checkpoint is for.
	Branch *string `json:"branch,omitempty" yaml:"branch,omitempty"`

	// Version is the version of the entity that the checkpoint is for.
	// This may be a container image tag, a git tag, or some other version.
	Version *string `json:"version,omitempty" yaml:"version,omitempty"`

	// Digest is the digest of the entity that the checkpoint is for.
	// This may be a container image digest, or some other digest.
	Digest *string `json:"digest,omitempty" yaml:"digest,omitempty"`

	// HTTPURL is the URL that was used to verify the entity.
	HTTPURL *string `json:"httpURL,omitempty" yaml:"httpURL,omitempty"`

	// HTTPMethod is the HTTP method that was used to verify the entity.
	HTTPMethod *string `json:"httpMethod,omitempty" yaml:"httpMethod,omitempty"`
}

// NewCheckpointV1Now creates a new CheckpointV1 with the current time.
func NewCheckpointV1Now() *CheckpointEnvelopeV1 {
	return NewCheckpointV1(time.Now())
}

// NewCheckpointV1 creates a new CheckpointV1 with the given timestamp.
func NewCheckpointV1(timestamp time.Time) *CheckpointEnvelopeV1 {
	return &CheckpointEnvelopeV1{
		Version: V1,
		Checkpoint: CheckpointV1{
			Timestamp: timestamp,
		},
	}
}

// WithCommitHash sets the commit hash on the checkpoint.
func (c *CheckpointEnvelopeV1) WithCommitHash(commitHash string) *CheckpointEnvelopeV1 {
	c.Checkpoint.CommitHash = &commitHash
	return c
}

// WithBranch sets the branch on the checkpoint.
func (c *CheckpointEnvelopeV1) WithBranch(branch string) *CheckpointEnvelopeV1 {
	c.Checkpoint.Branch = &branch
	return c
}

// WithVersion sets the version on the checkpoint.
func (c *CheckpointEnvelopeV1) WithVersion(version string) *CheckpointEnvelopeV1 {
	c.Checkpoint.Version = &version
	return c
}

// WithDigest sets the digest on the checkpoint.
func (c *CheckpointEnvelopeV1) WithDigest(digest string) *CheckpointEnvelopeV1 {
	c.Checkpoint.Digest = &digest
	return c
}

// WithHTTP sets the HTTP URL and method on the checkpoint.
func (c *CheckpointEnvelopeV1) WithHTTP(url, method string) *CheckpointEnvelopeV1 {
	c.Checkpoint.HTTPURL = &url
	c.Checkpoint.HTTPMethod = &method
	return c
}

// ToJSON marshals the checkpoint to JSON.
func (c *CheckpointEnvelopeV1) ToJSON() (json.RawMessage, error) {
	return json.Marshal(c)
}

// ToJSONorDefault marshals the checkpoint to JSON or returns a default value.
func (c *CheckpointEnvelopeV1) ToJSONorDefault(def json.RawMessage) (json.RawMessage, error) {
	if c == nil {
		return def, nil
	}

	js, err := c.ToJSON()
	if err != nil {
		return def, err
	}

	return js, nil
}
