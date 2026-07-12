// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oidc

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"

	"github.com/goharbor/harbor/src/common/utils"
	"github.com/goharbor/harbor/src/lib/config"
	"github.com/goharbor/harbor/src/pkg/oidc/dao"
)

// SecretVerifyError wraps the different errors happened when verifying a secret for OIDC user.  When seeing this error,
// the caller should consider this an authentication error.
type SecretVerifyError struct {
	cause error
}

func (se *SecretVerifyError) Error() string {
	return fmt.Sprintf("failed to verify the secret: %v", se.cause)
}

func verifyError(err error) error {
	return &SecretVerifyError{err}
}

// SecretManager is the interface for store and verify the secret
type SecretManager interface {
	// VerifySecret verifies the secret for an OIDC user.
	VerifySecret(ctx context.Context, username string, secret string) error
}

type keyGetter struct {
	sync.RWMutex
	key string
}

func (kg *keyGetter) encryptKey() (string, error) {
	kg.RLock()
	if kg.key == "" {
		kg.RUnlock()
		kg.Lock()
		defer kg.Unlock()
		if kg.key == "" {
			k, err := config.SecretKey()
			if err != nil {
				return "", err
			}
			kg.key = k
		}
	} else {
		defer kg.RUnlock()
	}
	return kg.key, nil
}

var keyLoader = &keyGetter{}

type defaultManager struct {
	metaDao dao.MetaDAO
}

var m SecretManager = &defaultManager{
	metaDao: dao.NewMetaDao(),
}

// VerifySecret verifies the secret for an OIDC user.
func (dm *defaultManager) VerifySecret(ctx context.Context, username string, secret string) error {
	oidcUser, err := dm.metaDao.GetByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("failed to get oidc user info, error: %v", err)
	}
	if oidcUser == nil {
		return fmt.Errorf("user is not onboarded as OIDC user, username: %s", username)
	}
	key, err := keyLoader.encryptKey()
	if err != nil {
		return fmt.Errorf("failed to load the key for encryption/decryption： %v", err)
	}
	plainSecret, err := utils.ReversibleDecrypt(oidcUser.Secret, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt secret from DB: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(plainSecret)) != 1 {
		return verifyError(fmt.Errorf("secret mismatch, username: %s", username))
	}
	return nil
}

// VerifySecret calls the manager to verify the secret.
func VerifySecret(ctx context.Context, name string, secret string) error {
	return m.VerifySecret(ctx, name, secret)
}
