package fs4strings

const (
	// AWS4HmacSha256 is a hashing algorithm for browser based uploads.
	AWS4HmacSha256 = "AWS4-HMAC-SHA256"
	// CredentialScope is a scope used while constructing credential string for browser based uploads.
	CredentialScope = "s3/aws4_request"

	// Strings used to build conditions map.
	// Required:

	// Key key
	Key = "key"
	// Policy policy
	Policy = "policy"
	// XAMZCredential x-amz-credential
	XAMZCredential = "x-amz-credential"
	// XAMZAlgorithm x-amz-algorithm
	XAMZAlgorithm = "x-amz-algorithm"
	// XAMZSignature x-amz-signature
	XAMZSignature = "x-amz-signature"
	// XAMZDate x-amz-date
	XAMZDate = "x-amz-date"

	// Optional:

	// Acl acl
	Acl = "acl"
	// Bucket bucket
	Bucket = "bucket"
	// Content-Type Content-Type
	ContentType = "Content-Type"
	// SuccessActionRedirect success_action_redirect
	SuccessActionRedirect = "success_action_redirect"
	// SuccessActionStatus success_action_status
	SuccessActionStatus = "success_action_status"
	// XAMZSecurityToken x-amz-security-token
	XAMZSecurityToken = "x-amz-security-token"
)
