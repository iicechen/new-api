package model

import (
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/require"
)

func TestChannelKeyIsEncryptedAtRest(t *testing.T) {
	truncateTables(t)
	previousSecret := common.CryptoSecret
	common.CryptoSecret = strings.Repeat("k", 48)
	t.Cleanup(func() { common.CryptoSecret = previousSecret })

	plain := "sk-test-channel-secret"
	channel := &Channel{
		Type:   1,
		Key:    plain,
		Status: common.ChannelStatusEnabled,
		Name:   "encrypted-channel",
	}
	require.NoError(t, DB.Create(channel).Error)

	var rawKey string
	require.NoError(t, DB.Model(&Channel{}).Select("key").Where("id = ?", channel.Id).Scan(&rawKey).Error)
	require.True(t, common.IsEncryptedSecret(rawKey))
	require.NotContains(t, rawKey, plain)

	fetched, err := GetChannelById(channel.Id, true)
	require.NoError(t, err)
	require.Equal(t, plain, fetched.Key)
}

func TestUpdateChannelKeyEncryptsDirectKeyUpdates(t *testing.T) {
	truncateTables(t)
	previousSecret := common.CryptoSecret
	common.CryptoSecret = strings.Repeat("m", 48)
	t.Cleanup(func() { common.CryptoSecret = previousSecret })

	channel := &Channel{
		Type:   1,
		Key:    "sk-original",
		Status: common.ChannelStatusEnabled,
		Name:   "encrypted-update-channel",
	}
	require.NoError(t, DB.Create(channel).Error)

	plain := `{"access_token":"codex-access-token","refresh_token":"codex-refresh-token"}`
	require.NoError(t, UpdateChannelKey(channel.Id, plain))

	var rawKey string
	require.NoError(t, DB.Model(&Channel{}).Select("key").Where("id = ?", channel.Id).Scan(&rawKey).Error)
	require.True(t, common.IsEncryptedSecret(rawKey))
	require.NotContains(t, rawKey, "codex-access-token")
	require.NotContains(t, rawKey, "codex-refresh-token")

	fetched, err := GetChannelById(channel.Id, true)
	require.NoError(t, err)
	require.Equal(t, plain, fetched.Key)
}
