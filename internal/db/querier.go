// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.23.0

package db

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

type Querier interface {
	AddUserProject(ctx context.Context, arg AddUserProjectParams) (UserProject, error)
	AddUserRole(ctx context.Context, arg AddUserRoleParams) (UserRole, error)
	CountProfilesByEntityType(ctx context.Context) ([]CountProfilesByEntityTypeRow, error)
	CountUsers(ctx context.Context) (int64, error)
	CreateAccessToken(ctx context.Context, arg CreateAccessTokenParams) (ProviderAccessToken, error)
	CreateArtifact(ctx context.Context, arg CreateArtifactParams) (Artifact, error)
	CreateArtifactVersion(ctx context.Context, arg CreateArtifactVersionParams) (ArtifactVersion, error)
	CreateOrganization(ctx context.Context, arg CreateOrganizationParams) (Project, error)
	CreateProfile(ctx context.Context, arg CreateProfileParams) (Profile, error)
	CreateProfileForEntity(ctx context.Context, arg CreateProfileForEntityParams) (EntityProfile, error)
	CreateProject(ctx context.Context, arg CreateProjectParams) (Project, error)
	CreateProvider(ctx context.Context, arg CreateProviderParams) (Provider, error)
	CreatePullRequest(ctx context.Context, arg CreatePullRequestParams) (PullRequest, error)
	CreateRepository(ctx context.Context, arg CreateRepositoryParams) (Repository, error)
	CreateRole(ctx context.Context, arg CreateRoleParams) (Role, error)
	CreateRuleType(ctx context.Context, arg CreateRuleTypeParams) (RuleType, error)
	CreateSessionState(ctx context.Context, arg CreateSessionStateParams) (SessionStore, error)
	CreateSigningKey(ctx context.Context, arg CreateSigningKeyParams) (SigningKey, error)
	CreateUser(ctx context.Context, arg CreateUserParams) (User, error)
	DeleteAccessToken(ctx context.Context, arg DeleteAccessTokenParams) error
	DeleteArtifact(ctx context.Context, id uuid.UUID) error
	DeleteArtifactVersion(ctx context.Context, id uuid.UUID) error
	DeleteExpiredSessionStates(ctx context.Context) error
	DeleteOldArtifactVersions(ctx context.Context, arg DeleteOldArtifactVersionsParams) error
	DeleteOrganization(ctx context.Context, id uuid.UUID) error
	DeleteProfile(ctx context.Context, id uuid.UUID) error
	DeleteProfileForEntity(ctx context.Context, arg DeleteProfileForEntityParams) error
	DeleteProject(ctx context.Context, id uuid.UUID) ([]DeleteProjectRow, error)
	DeleteProvider(ctx context.Context, arg DeleteProviderParams) error
	DeletePullRequest(ctx context.Context, arg DeletePullRequestParams) error
	DeleteRepository(ctx context.Context, id uuid.UUID) error
	DeleteRole(ctx context.Context, id int32) error
	DeleteRuleInstantiation(ctx context.Context, arg DeleteRuleInstantiationParams) error
	DeleteRuleStatusesForProfileAndRuleType(ctx context.Context, arg DeleteRuleStatusesForProfileAndRuleTypeParams) error
	DeleteRuleType(ctx context.Context, id uuid.UUID) error
	DeleteSessionState(ctx context.Context, id int32) error
	DeleteSessionStateByProjectID(ctx context.Context, arg DeleteSessionStateByProjectIDParams) error
	DeleteSigningKey(ctx context.Context, arg DeleteSigningKeyParams) error
	DeleteUser(ctx context.Context, id int32) error
	GetAccessTokenByProjectID(ctx context.Context, arg GetAccessTokenByProjectIDParams) (ProviderAccessToken, error)
	GetAccessTokenByProvider(ctx context.Context, provider string) ([]ProviderAccessToken, error)
	GetAccessTokenSinceDate(ctx context.Context, arg GetAccessTokenSinceDateParams) (ProviderAccessToken, error)
	GetArtifactByID(ctx context.Context, id uuid.UUID) (GetArtifactByIDRow, error)
	GetArtifactVersionByID(ctx context.Context, id uuid.UUID) (ArtifactVersion, error)
	GetArtifactVersionBySha(ctx context.Context, sha string) (ArtifactVersion, error)
	GetChildrenProjects(ctx context.Context, id uuid.UUID) ([]GetChildrenProjectsRow, error)
	GetEntityProfileByProjectAndName(ctx context.Context, arg GetEntityProfileByProjectAndNameParams) ([]GetEntityProfileByProjectAndNameRow, error)
	// GetFeatureInProject verifies if a feature is available for a specific project.
	// It returns the settings for the feature if it is available.
	GetFeatureInProject(ctx context.Context, arg GetFeatureInProjectParams) (json.RawMessage, error)
	GetOrganization(ctx context.Context, id uuid.UUID) (Project, error)
	GetOrganizationByName(ctx context.Context, name string) (Project, error)
	GetOrganizationForUpdate(ctx context.Context, name string) (Project, error)
	GetParentProjects(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error)
	GetParentProjectsUntil(ctx context.Context, arg GetParentProjectsUntilParams) ([]uuid.UUID, error)
	GetProfileByID(ctx context.Context, id uuid.UUID) (Profile, error)
	GetProfileByIDAndLock(ctx context.Context, id uuid.UUID) (Profile, error)
	GetProfileByNameAndLock(ctx context.Context, arg GetProfileByNameAndLockParams) (Profile, error)
	GetProfileByProjectAndID(ctx context.Context, arg GetProfileByProjectAndIDParams) ([]GetProfileByProjectAndIDRow, error)
	GetProfileForEntity(ctx context.Context, arg GetProfileForEntityParams) (EntityProfile, error)
	GetProfileStatusByIdAndProject(ctx context.Context, arg GetProfileStatusByIdAndProjectParams) (GetProfileStatusByIdAndProjectRow, error)
	GetProfileStatusByNameAndProject(ctx context.Context, arg GetProfileStatusByNameAndProjectParams) (GetProfileStatusByNameAndProjectRow, error)
	GetProfileStatusByProject(ctx context.Context, projectID uuid.UUID) ([]GetProfileStatusByProjectRow, error)
	GetProjectByID(ctx context.Context, id uuid.UUID) (Project, error)
	GetProjectByName(ctx context.Context, name string) (Project, error)
	GetProjectIDPortBySessionState(ctx context.Context, sessionState string) (GetProjectIDPortBySessionStateRow, error)
	GetProviderByID(ctx context.Context, arg GetProviderByIDParams) (Provider, error)
	GetProviderByName(ctx context.Context, arg GetProviderByNameParams) (Provider, error)
	GetPullRequest(ctx context.Context, arg GetPullRequestParams) (PullRequest, error)
	GetRepositoryByID(ctx context.Context, id uuid.UUID) (Repository, error)
	GetRepositoryByIDAndProject(ctx context.Context, arg GetRepositoryByIDAndProjectParams) (Repository, error)
	GetRepositoryByRepoID(ctx context.Context, repoID int32) (Repository, error)
	GetRepositoryByRepoName(ctx context.Context, arg GetRepositoryByRepoNameParams) (Repository, error)
	GetRoleByID(ctx context.Context, id int32) (Role, error)
	GetRoleByName(ctx context.Context, arg GetRoleByNameParams) (Role, error)
	GetRootProjects(ctx context.Context) ([]Project, error)
	GetRuleTypeByID(ctx context.Context, id uuid.UUID) (RuleType, error)
	GetRuleTypeByName(ctx context.Context, arg GetRuleTypeByNameParams) (RuleType, error)
	GetSessionState(ctx context.Context, id int32) (SessionStore, error)
	GetSessionStateByProjectID(ctx context.Context, projectID uuid.UUID) (SessionStore, error)
	GetSigningKeyByIdentifier(ctx context.Context, keyIdentifier string) (SigningKey, error)
	GetSigningKeyByProjectID(ctx context.Context, projectID uuid.UUID) (SigningKey, error)
	GetUserByID(ctx context.Context, id int32) (User, error)
	GetUserBySubject(ctx context.Context, identitySubject string) (User, error)
	GetUserProjects(ctx context.Context, userID int32) ([]GetUserProjectsRow, error)
	GetUserRoles(ctx context.Context, userID int32) ([]GetUserRolesRow, error)
	GlobalListProviders(ctx context.Context) ([]Provider, error)
	ListAllRepositories(ctx context.Context, provider string) ([]Repository, error)
	ListArtifactVersionsByArtifactID(ctx context.Context, arg ListArtifactVersionsByArtifactIDParams) ([]ArtifactVersion, error)
	ListArtifactVersionsByArtifactIDAndTag(ctx context.Context, arg ListArtifactVersionsByArtifactIDAndTagParams) ([]ArtifactVersion, error)
	ListArtifactsByRepoID(ctx context.Context, repositoryID uuid.UUID) ([]Artifact, error)
	ListOrganizations(ctx context.Context, arg ListOrganizationsParams) ([]Project, error)
	ListProfilesByProjectID(ctx context.Context, projectID uuid.UUID) ([]ListProfilesByProjectIDRow, error)
	// get profile information that instantiate a rule. This is done by joining the profiles with entity_profiles, then correlating those
	// with entity_profile_rules. The rule_type_id is used to filter the results. Note that we only really care about the overal profile,
	// so we only return the profile information. We also should group the profiles so that we don't get duplicates.
	ListProfilesInstantiatingRuleType(ctx context.Context, ruleTypeID uuid.UUID) ([]ListProfilesInstantiatingRuleTypeRow, error)
	ListProvidersByProjectID(ctx context.Context, projectID uuid.UUID) ([]Provider, error)
	ListRegisteredRepositoriesByProjectIDAndProvider(ctx context.Context, arg ListRegisteredRepositoriesByProjectIDAndProviderParams) ([]Repository, error)
	ListRepositoriesByOwner(ctx context.Context, arg ListRepositoriesByOwnerParams) ([]Repository, error)
	ListRepositoriesByProjectID(ctx context.Context, arg ListRepositoriesByProjectIDParams) ([]Repository, error)
	ListRoles(ctx context.Context, arg ListRolesParams) ([]Role, error)
	ListRolesByProjectID(ctx context.Context, arg ListRolesByProjectIDParams) ([]Role, error)
	ListRuleEvaluationsByProfileId(ctx context.Context, arg ListRuleEvaluationsByProfileIdParams) ([]ListRuleEvaluationsByProfileIdRow, error)
	ListRuleTypesByProviderAndProject(ctx context.Context, arg ListRuleTypesByProviderAndProjectParams) ([]RuleType, error)
	ListUsers(ctx context.Context, arg ListUsersParams) ([]User, error)
	ListUsersByOrganization(ctx context.Context, arg ListUsersByOrganizationParams) ([]User, error)
	ListUsersByProject(ctx context.Context, arg ListUsersByProjectParams) ([]User, error)
	ListUsersByRoleId(ctx context.Context, roleID int32) ([]int32, error)
	UpdateAccessToken(ctx context.Context, arg UpdateAccessTokenParams) (ProviderAccessToken, error)
	UpdateOrganization(ctx context.Context, arg UpdateOrganizationParams) (Project, error)
	UpdateProfile(ctx context.Context, arg UpdateProfileParams) (Profile, error)
	UpdateProfileForEntity(ctx context.Context, arg UpdateProfileForEntityParams) (EntityProfile, error)
	// set clone_url if the value is not an empty string
	UpdateRepository(ctx context.Context, arg UpdateRepositoryParams) (Repository, error)
	UpdateRepositoryByID(ctx context.Context, arg UpdateRepositoryByIDParams) (Repository, error)
	UpdateRole(ctx context.Context, arg UpdateRoleParams) (Role, error)
	UpdateRuleType(ctx context.Context, arg UpdateRuleTypeParams) error
	UpsertArtifact(ctx context.Context, arg UpsertArtifactParams) (Artifact, error)
	UpsertArtifactVersion(ctx context.Context, arg UpsertArtifactVersionParams) (ArtifactVersion, error)
	UpsertPullRequest(ctx context.Context, arg UpsertPullRequestParams) (PullRequest, error)
	UpsertRuleDetailsAlert(ctx context.Context, arg UpsertRuleDetailsAlertParams) (uuid.UUID, error)
	UpsertRuleDetailsEval(ctx context.Context, arg UpsertRuleDetailsEvalParams) (uuid.UUID, error)
	UpsertRuleDetailsRemediate(ctx context.Context, arg UpsertRuleDetailsRemediateParams) (uuid.UUID, error)
	UpsertRuleEvaluations(ctx context.Context, arg UpsertRuleEvaluationsParams) (uuid.UUID, error)
	UpsertRuleInstantiation(ctx context.Context, arg UpsertRuleInstantiationParams) (EntityProfileRule, error)
}

var _ Querier = (*Queries)(nil)
