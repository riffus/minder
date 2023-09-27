// Copyright 2023 Stacklok, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlplane

// TODO: support refresh token
//func TestRefreshToken_gRPC(t *testing.T) {
//	t.Parallel()
//
//	tmpdir := t.TempDir()
//	atPrivPath := filepath.Join(tmpdir, "access_token_private.pem")
//	atPubPath := filepath.Join(tmpdir, "access_token_public.pem")
//	rtPrivPath := filepath.Join(tmpdir, "refresh_token_private.pem")
//	rtPubPath := filepath.Join(tmpdir, "refresh_token_public.pem")
//
//	// prepare keys for signing tokens
//	viper.SetDefault("auth.access_token_private_key", atPrivPath)
//	viper.SetDefault("auth.access_token_public_key", atPubPath)
//	viper.SetDefault("auth.refresh_token_private_key", rtPrivPath)
//	viper.SetDefault("auth.refresh_token_public_key", rtPubPath)
//	viper.SetDefault("auth.token_expiry", 3600)
//	viper.SetDefault("auth.refresh_expiry", 86400)
//	err := util.RandomKeypairFile(2048, atPrivPath, atPubPath)
//	require.NoError(t, err, "Error generating access token key pair")
//
//	err = util.RandomKeypairFile(2048, rtPrivPath, rtPubPath)
//	require.NoError(t, err, "Error generating refresh token key pair")
//
//	ctrl := gomock.NewController(t)
//	defer ctrl.Finish()
//
//	mockStoreToken := mockdb.NewMockStore(ctrl)
//	mockStore := mockdb.NewMockStore(ctrl)
//
//	ctxToken := context.Background()
//	// mocked calls
//	mockStoreToken.EXPECT().GetUserByID(ctxToken, gomock.Any())
//	mockStoreToken.EXPECT().GetUserGroups(ctxToken, gomock.Any())
//	mockStoreToken.EXPECT().GetUserRoles(ctxToken, gomock.Any())
//	// generate a token
//	_, refreshToken, _, _, _, err := generateToken(ctxToken, mockStoreToken, 1)
//	if err != nil {
//		t.Fatalf("Error generating token: %v", err)
//	}
//
//	// Create header metadata
//	md := metadata.New(map[string]string{
//		"refresh-token": refreshToken,
//	})
//
//	// Create a new context with added header metadata
//	ctx := context.Background()
//	ctx = metadata.NewIncomingContext(ctx, md)
//	server := newDefaultServer(t, mockStore)
//	mockStore.EXPECT().GetUserByID(gomock.Any(), gomock.Any()).Times(2)
//	mockStore.EXPECT().GetUserGroups(gomock.Any(), gomock.Any())
//	mockStore.EXPECT().GetUserRoles(gomock.Any(), gomock.Any())
//
//	// validate the status of the output
//	res, err := server.RefreshToken(ctx, &pb.RefreshTokenRequest{})
//	assert.NoError(t, err)
//	assert.NotNil(t, res)
//	assert.NotNil(t, res.AccessToken)
//
//}
