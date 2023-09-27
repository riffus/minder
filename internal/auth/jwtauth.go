//
// Copyright 2023 Stacklok, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// NOTE: This file is for stubbing out client code for proof of concept
// purposes. It will / should be removed in the future.
// Until then, it is not covered by unit tests and should not be used
// It does make a good example of how to use the generated client code
// for others to use as a reference.

package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
	"github.com/stacklok/mediator/internal/db"
	"golang.org/x/exp/slices"
)

// RoleInfo contains the role information for a user
type RoleInfo struct {
	RoleID         int32 `json:"role_id"`
	IsAdmin        bool  `json:"is_admin"`
	GroupID        int32 `json:"group_id"`
	OrganizationID int32 `json:"organization_id"`
}

// UserPermissions contains the permissions for a user
type UserPermissions struct {
	UserId         int32
	GroupIds       []int32
	Roles          []RoleInfo
	OrganizationId int32
}

type JwtValidator interface {
	ParseAndValidate(tokenString string) (openid.Token, error)
}

type JwkSetJwtValidator struct {
	ctx     context.Context
	jwksUrl string
	jwks    *jwk.Cache
}

func (j *JwkSetJwtValidator) ParseAndValidate(tokenString string) (openid.Token, error) {
	set, err := j.jwks.Get(j.ctx, j.jwksUrl)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseString(tokenString, jwt.WithKeySet(set), jwt.WithValidate(true), jwt.WithToken(openid.New()))
	if err != nil {
		return nil, err
	}

	openIdToken, ok := token.(openid.Token)
	if !ok {
		return nil, fmt.Errorf("provided token was not an OpenID token")
	}
	return openIdToken, nil
}

func NewJwtValidator(ctx context.Context, jwksUrl string) (JwtValidator, error) {
	// Cache the JWK set
	// The cache will refresh every 15 minutes by default
	jwks := jwk.NewCache(ctx)
	err := jwks.Register(jwksUrl)
	if err != nil {
		return nil, err
	}

	// Refresh the JWKS once before starting
	_, err = jwks.Refresh(ctx, jwksUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh identity provider JWKS: %s\n", err)
	}

	return &JwkSetJwtValidator{
		ctx:     ctx,
		jwksUrl: jwksUrl,
		jwks:    jwks,
	}, nil
}

// VerifyToken verifies the token string and returns the user ID
// nolint:gocyclo
func VerifyToken(ctx context.Context, tokenString string, store db.Store, vldtr JwtValidator) (UserPermissions, error) {
	var userPermissions UserPermissions

	token, err := vldtr.ParseAndValidate(tokenString)
	if err != nil {
		return userPermissions, err
	}

	subject := token.Subject()

	// TODO:  Consider moving the claim fetching out of this method, because this may be called when the user does not exist in the DB which cases GetUserClaims to error.

	// get user authorities from the database
	userPermissions, _ = GetUserPermissions(ctx, store, subject)

	return userPermissions, nil
}

// VerifyRefreshToken verifies the refresh token string and returns the user ID
//func VerifyRefreshToken(tokenString string, publicKey *rsa.PublicKey, store db.Store) (int32, error) {
//	if publicKey == nil {
//		return 0, fmt.Errorf("invalid key")
//	}
//	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
//		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
//			return nil, status.Error(codes.InvalidArgument, "unexpected signing method")
//		}
//		return publicKey, nil
//	})
//
//	if err != nil {
//		return 0, err
//	}
//
//	claims, ok := token.Claims.(jwt.MapClaims)
//	if !ok || !token.Valid {
//		return 0, fmt.Errorf("invalid token")
//	}
//
//	// validate that iat is on the past
//	if claims, ok := token.Claims.(jwt.MapClaims); ok {
//		if !claims.VerifyIssuedAt(time.Now().Unix(), true) {
//			return 0, fmt.Errorf("invalid token")
//		}
//	}
//
//	// we have the user id, check if exists
//	userId := int32(claims["userId"].(float64))
//	_, err = store.GetUserByID(context.Background(), userId)
//	if err != nil {
//		return 0, fmt.Errorf("invalid token")
//	}
//
//	return userId, nil
//}

// GetUserPermissions returns the user permissions from the database for the given user
func GetUserPermissions(ctx context.Context, store db.Store, subject string) (UserPermissions, error) {
	emptyClaims := UserPermissions{}

	// read all information for user claims
	userInfo, err := store.GetUserBySubject(ctx, subject)
	if err != nil {
		return emptyClaims, fmt.Errorf("failed to read user")
	}

	// read groups and add id to claims
	gs, err := store.GetUserGroups(ctx, userInfo.ID)
	if err != nil {
		return emptyClaims, fmt.Errorf("failed to get groups")
	}
	var groups []int32
	for _, g := range gs {
		groups = append(groups, g.ID)
	}

	// read roles and add details to claims
	rs, err := store.GetUserRoles(ctx, userInfo.ID)
	if err != nil {
		return emptyClaims, fmt.Errorf("failed to get roles")
	}

	var roles []RoleInfo
	for _, r := range rs {
		roles = append(roles, RoleInfo{RoleID: r.ID, IsAdmin: r.IsAdmin, GroupID: r.GroupID.Int32, OrganizationID: r.OrganizationID})
	}

	claims := UserPermissions{
		UserId:         userInfo.ID,
		Roles:          roles,
		GroupIds:       groups,
		OrganizationId: userInfo.OrganizationID,
	}

	return claims, nil
}

var tokenContextKey struct{}

// GetPermissionsFromContext returns the claims from the context, or an empty default
func GetPermissionsFromContext(ctx context.Context) UserPermissions {
	claims, ok := ctx.Value(tokenContextKey).(UserPermissions)
	if !ok {
		return UserPermissions{UserId: -1, OrganizationId: -1}
	}
	return claims
}

// WithClaimContext stores the specified UserClaim in the context.
func WithClaimContext(ctx context.Context, claims UserPermissions) context.Context {
	return context.WithValue(ctx, tokenContextKey, claims)
}

// GetDefaultGroup returns the default group id for the user
func GetDefaultGroup(ctx context.Context) (int32, error) {
	claims := GetPermissionsFromContext(ctx)
	if len(claims.GroupIds) != 1 {
		return 0, errors.New("cannot get default group")
	}
	return claims.GroupIds[0], nil
}

// IsAuthorizedForGroup returns true if the user is authorized for the given group
func IsAuthorizedForGroup(ctx context.Context, groupId int32) bool {
	claims := GetPermissionsFromContext(ctx)

	return slices.Contains(claims.GroupIds, groupId)
}

// GetUserGroups returns all the groups where an user belongs to
func GetUserGroups(ctx context.Context) ([]int32, error) {
	claims := GetPermissionsFromContext(ctx)
	return claims.GroupIds, nil
}
