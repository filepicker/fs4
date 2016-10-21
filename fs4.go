/*
Package fs4 is a wrapper for the aws-sdk-go for most common cases used in Filestack.
FS4 stands for FileStack Simple Storage Service.
*/
package fs4

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// FS4 is the core struct.
type FS4 struct {
	config *S3Config
	BBU    *BBU
}

// BBU represents struct responsible for Browser Based Uploads.
type BBU struct {
	Conditions      map[string]string
	config          *S3Config
	minutesToExpiry int
	expiration      string
	dateString      string
	dateStringISO   string
	secretKey       string
	region          string
}

// bbuParams represents a struct from which base64 policy and signature are constructed.
type bbuParams struct {
	Conditions []map[string]string `json:"conditions"`
	Expiration string              `json:"expiration"`
	SecretKey  string              `json:"-"`
	Policy64   string              `json:"-"`
	Region     string              `json:"-"`
	Date       string              `json:"-"`
}

// BBUResponse represents a struct with data required to fill the html upload form fields.
type BBUResponse struct {
	URL         string `json:"url"`
	RedirectURI string `json:"success_action_redirect"`
	Credential  string `json:"x_amz_credential"`
	AccessKey   string `json:"aws_access_key_id"`
	Signature   string `json:"signature"`
	Policy      string `json:"policy"`
	Date        string `json:"x_amz_date"`
	Key         string `json:"key"`
}

// S3Config represents user's s3 application configuration.
type S3Config struct {
	AccessKey string
	SecretKey string
	Bucket    string
	Region    string
}

// NewClient returns new FS4 object initialized with s3Config.
func NewClient(s3Config *S3Config) *FS4 {
	return &FS4{
		config: s3Config,
	}
}

// NewBBU returns new BBU object initialized with conditions and for how long it will stay valid (number of minutes as integer).
func (fs4 *FS4) NewBBU(conditions map[string]string, minutesToExpiry int) {
	now := time.Now()
	dateString := dateString(now)
	fs4.BBU = *BBU{
		Conditions:    conditions,
		config:        fs4.config,
		dateString:    dateString,
		dateStringISO: dateStringISO(dateString),
		expiration:    expirationDate(now, minutesToExpiry),
	}
}

func (bbu *BBU) FormFields() ([]byte, error) {
	bbuParams := bbu.toParams()

	bbuResponse := &BBUResponse{
		URL:         bbu.bucketURL(),
		RedirectURI: bbu.Conditions[fs4strings.SuccessActionRedirect],
		AccessKey:   bbu.config.AccessKey,
		Credential:  bbu.config.credential(bbu.dateString),
		Key:         bbu.Conditions[fs4strings.Key],
		Date:        bbu.dateStringISO,
		Policy:      bbuParams.toPolicy(),
		Signature:   bbuParams.toSignature(),
	}

	return json.Marshal(bbuResponse)
}

func (bbu *BBU) toParams() *bbuParams {
	return &bbuParams{
		Conditions: bbu.Conditions,
		Expiration: bbu.expiration,
		Date:       bbu.dateString,
		SecretKey:  bbu.config.SecretKey,
		Region:     bbu.config.Region,
	}
}

func (bbu *BBU) Policy() string {
	return bbu.toParams().toPolicy()
}

func (bbu *BBU) Signature() string {
	return bbu.toParams().toSignature()
}

func (bbu *bbuParams) toPolicy() string {
	paramsJSON, err := json.Marshal(bbu)
	if err != nil {
		return ""
	}

	bbu.Policy64 = base64.StdEncoding.EncodeToString(paramsJSON)
	return bbu.Policy64
}

func (bbu *bbuParams) toSignature() string {
	if bbu.Policy64 == "" {
		bbu.toPolicy()
	}

	dateKey := shmacSHA256("AWS4"+bbu.config.SecretKey, bbu.Date)
	dateRegionKey := hmacSHA256(dateKey, bbu.config.Region)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, "s3")
	signingKey := hmacSHA256(dateRegionServiceKey, "aws4_request")

	return hmacToHex(signingKey, bbu.Policy64)
}

func (c *S3Config) credential(dateString string) string {
	return strings.Join([]string{c.AccessKey, dateString, c.Region, credentialScopeType}, "/")
}
