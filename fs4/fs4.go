/*
Package fs4 is a wrapper for the aws-sdk-go for most common cases used in Filestack.
FS4 stands for FileStack Simple Storage Service.
*/
package fs4

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	fs4s "github.com/pJes2/fs4/fs4strings"
)

// FS4 is the core struct.
type FS4 struct {
	config   *S3Config
	BBU      *BBU
	Uploader *Uploader
}

// Uploader represents object used to upload files to s3 bucket.
type Uploader struct {
	bucket   string
	uploader *s3manager.Uploader
	client   *s3.S3
}

// BBU represents struct responsible for Browser Based Uploads.
type BBU struct {
	Conditions      Conditions
	DateStringISO   string
	Credential      string
	config          *S3Config
	minutesToExpiry int
	expiration      string
	dateString      string
	secretKey       string
	region          string
}

// Conditions represents BBU conditions slice used to calculate policy and signature.
type Conditions []map[string]string

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
	Algorithm   string `json:"x_amz_algorithm"`
	Credential  string `json:"x_amz_credential"`
	AccessKey   string `json:"aws_access_key_id"`
	Signature   string `json:"signature"`
	Policy      string `json:"policy"`
	Date        string `json:"x_amz_date"`
	Key         string `json:"key"`
}

// S3Config represents user's s3 application configuration.
type S3Config struct {
	AccessKey  string
	SecretKey  string
	Bucket     string
	Region     string
	Accelerate bool
}

// NewClient returns new FS4 object initialized with s3Config.
func NewClient(s3Config *S3Config) *FS4 {
	return &FS4{
		config: s3Config,
	}
}

// UploadFile uploads provided file to s3 bucket.
func (u *Uploader) UploadFile(key, mimetype string, body io.Reader, expiry time.Duration) (string, error) {
	if _, err := u.uploader.Upload(&s3manager.UploadInput{
		Body:        body,
		Bucket:      aws.String(u.bucket),
		Key:         aws.String(key),
		ContentType: aws.String(mimetype),
	}); err != nil {
		return "", err
	}

	req, _ := u.client.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(u.bucket),
		Key:    aws.String(key),
	})

	return req.Presign(expiry)
}

// NewUploader initializes, sets to fs4.Uploader and returns a new Uploader.
func (fs4 *FS4) NewUploader() *Uploader {
	svc := prepareSVC(fs4.config)

	fs4.Uploader = &Uploader{
		bucket:   fs4.config.Bucket,
		client:   svc,
		uploader: s3manager.NewUploaderWithClient(svc),
	}

	return fs4.Uploader
}

// GetBucketRegion returns region of the bucket set in s3Config.
func GetBucketRegion(s3Config *S3Config) (string, error) {
	svc := prepareSVC(s3Config)

	params := &s3.GetBucketLocationInput{
		Bucket: aws.String(s3Config.Bucket),
	}

	resp, err := svc.GetBucketLocation(params)
	if err != nil {
		return "", err
	}

	return *resp.LocationConstraint, nil
}

// HeadS3Object ...
func HeadS3Object(key string, s3Config *S3Config) {
	svc := prepareSVC(s3Config)

	params := &s3.HeadObjectInput{
		Bucket: aws.String(s3Config.Bucket),
		Key:    aws.String(key),
	}

	resp, err := svc.HeadObject(params)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(resp)
}

// prepareSVC returns s3.S3 object configured with data from s3Config.
func prepareSVC(s3Config *S3Config) *s3.S3 {
	creds := credentials.NewStaticCredentials(s3Config.AccessKey, s3Config.SecretKey, "")
	cfg := aws.NewConfig().WithRegion(s3Config.Region).WithCredentials(creds)
	return s3.New(session.New(), cfg)
}

// NewBBU sets to fs4.BBU and returns new BBU object initialized with number of minutes until the object expires.
func (fs4 *FS4) NewBBU(minutesToExpiry int) *BBU {
	now := time.Now()
	dateString := dateString(now)
	fs4.BBU = &BBU{
		config:        fs4.config,
		dateString:    dateString,
		DateStringISO: dateStringISO(dateString),
		Credential:    fs4.config.credential(dateString),
		expiration:    expirationDate(now, minutesToExpiry),
	}

	fs4.BBU.setDefaultConditions()

	return fs4.BBU
}

// setDefaultConditions sets condition required to create policy and by HTML form.
func (bbu *BBU) setDefaultConditions() *BBU {
	bbu.Conditions = []map[string]string{
		map[string]string{
			fs4s.Bucket: bbu.config.Bucket,
		},
		map[string]string{
			fs4s.XAMZCredential: bbu.Credential,
		},
		map[string]string{
			fs4s.XAMZAlgorithm: fs4s.AWS4HmacSha256,
		},
		map[string]string{
			fs4s.XAMZDate: bbu.DateStringISO,
		},
	}

	return bbu
}

// AddCondition adds a key-value condition to Conditions slice.
func (bbu *BBU) AddCondition(key, value string) *BBU {
	bbu.Conditions = append(bbu.Conditions, map[string]string{key: value})

	return bbu
}

// FormFields returns JSON response required to fill the html upload form fields.
func (bbu *BBU) FormFields() ([]byte, error) {
	bbuParams := bbu.toParams()

	redirectURI := bbu.conditionForKey(fs4s.SuccessActionRedirect)
	key := bbu.conditionForKey(fs4s.Key)

	bbuResponse := &BBUResponse{
		URL:         bbu.bucketURL(),
		RedirectURI: redirectURI,
		AccessKey:   bbu.config.AccessKey,
		Algorithm:   fs4s.AWS4HmacSha256,
		Credential:  bbu.config.credential(bbu.dateString),
		Key:         key,
		Date:        bbu.DateStringISO,
		Policy:      bbuParams.toPolicy(),
		Signature:   bbuParams.toSignature(),
	}

	return json.Marshal(bbuResponse)
}

func (bbu *BBU) conditionForKey(key string) string {
	for i := range bbu.Conditions {
		v, ok := bbu.Conditions[i][key]
		if ok {
			return v
		}
	}

	return ""
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

func (bbu *BBU) bucketURL() string {
	s3s := ".s3"
	if bbu.config.Accelerate {
		s3s = ".s3-accelerate"
	}

	return "http://" + bbu.config.Bucket + s3s + ".amazonaws.com/"
}

// Policy returns base64 policy from conditions, s3 config and date set on BBU.
func (bbu *BBU) Policy() string {
	return bbu.toParams().toPolicy()
}

// Signature returns signature calculated from policy, s3 config and date set on BBU.
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

	dateKey := shmacSHA256("AWS4"+bbu.SecretKey, bbu.Date)
	dateRegionKey := hmacSHA256(dateKey, bbu.Region)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, "s3")
	signingKey := hmacSHA256(dateRegionServiceKey, "aws4_request")

	return hmacToHex(signingKey, bbu.Policy64)
}

func (c *S3Config) credential(dateString string) string {
	return strings.Join([]string{c.AccessKey, dateString, c.Region, fs4s.CredentialScope}, "/")
}
