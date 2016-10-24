package fs4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strings"
	"time"
)

// shmacSHA256 returns HMAC-SHA256 hash from key and message strings.
func shmacSHA256(key, message string) hash.Hash {
	sig := hmac.New(sha256.New, []byte(key))
	sig.Write([]byte(message))
	return sig
}

// hmacSHA256 returns HMAC-SHA256 hash from key hash and message string.
func hmacSHA256(key hash.Hash, message string) hash.Hash {
	return shmacSHA256(string(key.Sum(nil)), message)
}

// hmacToHex returns hex string from HMAC-SHA256 key hash and message string.
func hmacToHex(key hash.Hash, message string) string {
	return hex.EncodeToString(hmacSHA256(key, message).Sum(nil))
}

// dateString returns "yyyymmdd" date string from Time.
func dateString(now time.Time) string {
	return strings.Replace(now.Format("2006-01-02"), "-", "", -1)
}

// dateStringISO returns "dateStringT000000Z" string.
func dateStringISO(dateString string) string {
	return dateString + "T000000Z"
}

// expirationDate returns "yyyy-mm-ddThh:mm:ss.000Z" date string from Time and timeToExpiry as a number of minutes.
// The date string returned is 5 minutes into the future.
func expirationDate(now time.Time, timeToExpiry int) string {
	expiration := now.Add(time.Duration(timeToExpiry) * time.Minute).Format(time.RFC3339)
	return strings.Split(expiration, "+")[0] + ".000Z"
}
