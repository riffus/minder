// Copyright 2023 Stacklok, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlplane

import (
	"context"
	"github.com/stacklok/mediator/internal/auth"
	pb "github.com/stacklok/mediator/pkg/api/protobuf/go/mediator/v1"
)

//func (s *Server) parseRefreshToken(token string, store db.Store) (int32, error) {
//	pubKeyData, err := s.cfg.Auth.GetRefreshTokenPublicKey()
//	if err != nil {
//		return 0, fmt.Errorf("failed to read refresh token public key file: %w", err)
//	}
//
//	userId, err := auth.VerifyRefreshToken(token, pubKeyData, store)
//	if err != nil {
//		return 0, fmt.Errorf("failed to verify token: %v", err)
//	}
//	return userId, nil
//}

// RefreshToken refreshes the access token
func (s *Server) RefreshToken(ctx context.Context, _ *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	//md, ok := metadata.FromIncomingContext(ctx)
	//if !ok {
	//	// Metadata not found
	//	return nil, status.Errorf(codes.Unauthenticated, "no metadata found")
	//}
	//refresh := ""
	//if tokens := md.Get("refresh-token"); len(tokens) > 0 {
	//	refresh = tokens[0]
	//}
	//if refresh == "" {
	//	return nil, status.Errorf(codes.Unauthenticated, "no refresh token found")
	//}
	//
	//userId, err := s.parseRefreshToken(refresh, s.store)
	//if err != nil {
	//	return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	//}
	//
	//// regenerate and return tokens
	//accessToken, _, accessTokenExpirationTime, _, _, err := s.generateToken(ctx, s.store, userId)
	//
	//if err != nil {
	//	return nil, status.Errorf(codes.Internal, "Failed to generate token")
	//}
	//return &pb.RefreshTokenResponse{
	//	AccessToken:          accessToken,
	//	AccessTokenExpiresIn: accessTokenExpirationTime,
	//}, nil
	// TODO: refresh
	return nil, nil
}

// Verify verifies the access token
func (*Server) Verify(ctx context.Context, _ *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	claims := auth.GetClaimsFromContext(ctx)
	if claims.UserId > 0 {
		return &pb.VerifyResponse{Status: "OK"}, nil
	}
	return &pb.VerifyResponse{Status: "KO"}, nil
}
