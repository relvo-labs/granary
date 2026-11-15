// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	miniogopolicy "github.com/minio/minio-go/v7/pkg/policy"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/pkg/v3/policy"
	"github.com/minio/pkg/v3/policy/condition"
	"github.com/relvo-labs/granary/internal/auth"
	"github.com/relvo-labs/granary/internal/handlers"
	xhttp "github.com/relvo-labs/granary/internal/http"
	"github.com/relvo-labs/granary/internal/logger"
)

// PolicySys - policy subsystem.
type PolicySys struct{}

// Get returns stored bucket policy
func (sys *PolicySys) Get(bucket string) (*policy.BucketPolicy, error) {
	policy, _, err := globalBucketMetadataSys.GetPolicyConfig(bucket)
	return policy, err
}

// IsAllowed - checks given policy args is allowed to continue the Rest API.
func (sys *PolicySys) IsAllowed(args policy.BucketPolicyArgs) bool {
	p, err := sys.Get(args.BucketName)
	if err == nil {
		return p.IsAllowed(args)
	}

	// Log unhandled errors.
	if _, ok := err.(BucketPolicyNotFound); !ok {
		internalLogIf(GlobalContext, err, logger.WarningKind)
	}

	// As policy is not available for given bucket name, returns IsOwner i.e.
	// operation is allowed only for owner.
	return args.IsOwner
}

// NewPolicySys - creates new policy system.
func NewPolicySys() *PolicySys {
	return &PolicySys{}
}

func getSTSConditionValues(r *http.Request, lc string, cred auth.Credentials) map[string][]string {
	m := make(map[string][]string)
	if d := r.Form.Get("DurationSeconds"); d != "" {
		m["DurationSeconds"] = []string{d}
	}
	return m
}

// objectTagConditions is server-owned policy input. It is never imported from
// HTTP condition names, and does not alter headers that were authenticated.
type objectTagConditions struct {
	existing  string
	request   string
	versionID *string
}

type objectTagConditionKey struct{}

func setExistingObjectTags(r *http.Request, userTags string) {
	values, _ := r.Context().Value(objectTagConditionKey{}).(objectTagConditions)
	values.existing = userTags
	*r = *r.WithContext(context.WithValue(r.Context(), objectTagConditionKey{}, values))
}

// Selected versions supplied by copy headers or multi-delete XML are not the
// destination request's versionId query parameter.
func setExistingObjectTagsForVersion(r *http.Request, userTags, versionID string) {
	setExistingObjectTags(r, userTags)
	values, _ := r.Context().Value(objectTagConditionKey{}).(objectTagConditions)
	values.versionID = &versionID
	*r = *r.WithContext(context.WithValue(r.Context(), objectTagConditionKey{}, values))
}

func setRequestObjectTags(r *http.Request, userTags string) {
	values, _ := r.Context().Value(objectTagConditionKey{}).(objectTagConditions)
	values.request = userTags
	*r = *r.WithContext(context.WithValue(r.Context(), objectTagConditionKey{}, values))
}

// Reserve names before importing raw headers/forms, including encoded aliases.
func reservedConditionName(name string) string {
	if decoded, err := url.QueryUnescape(name); err == nil {
		name = decoded
	}
	name = strings.ToLower(name)
	if prefix, rest, ok := strings.Cut(name, ":"); ok {
		switch prefix {
		case "aws", "s3", "jwt", "ldap", "sts", "svc":
			name = rest
		}
	}
	return name
}

func reservedTagCondition(name string) bool {
	name = reservedConditionName(name)
	return name == "existingobjecttag" || strings.HasPrefix(name, "existingobjecttag/") ||
		name == "requestobjecttag" || strings.HasPrefix(name, "requestobjecttag/") ||
		name == "requestobjecttagkeys"
}

var reservedConditionNames = func() map[string]bool {
	names := map[string]bool{
		"versionid": true, "object-lock-mode": true, "object-lock-legal-hold": true,
		"object-lock-retain-until-date": true, "object-lock-remaining-retention-days": true,
		"x-amz-signature-age": true,
	}
	for _, key := range condition.CommonKeys {
		names[reservedConditionName(key.Name())] = true
	}
	return names
}()

func reservedConditionInput(name string, claims map[string]any) bool {
	if reservedTagCondition(name) || reservedConditionNames[reservedConditionName(name)] {
		return true
	}
	for key := range claims {
		if reservedConditionName(name) == reservedConditionName(strings.TrimPrefix(key, "ldap")) {
			return true
		}
	}
	return false
}

func getConditionValues(r *http.Request, lc string, cred auth.Credentials) map[string][]string {
	currTime := UTCNow()

	var (
		username = cred.AccessKey
		claims   = cred.Claims
		groups   = cred.Groups
	)

	if cred.IsTemp() || cred.IsServiceAccount() {
		// For derived credentials, check the parent user's permissions.
		username = cred.ParentUser
	}

	principalType := "Anonymous"
	if username != "" {
		principalType = "User"
		if len(claims) > 0 {
			principalType = "AssumedRole"
		}
		if username == globalActiveCred.AccessKey {
			principalType = "Account"
		}
	}

	vid := r.Form.Get(xhttp.VersionID)
	if vid == "" {
		if u, err := url.Parse(r.Header.Get(xhttp.AmzCopySource)); err == nil {
			vid = u.Query().Get(xhttp.VersionID)
		}
	}

	if values, ok := r.Context().Value(objectTagConditionKey{}).(objectTagConditions); ok && values.versionID != nil {
		vid = *values.versionID
	}

	authType := getRequestAuthType(r)
	var signatureVersion string
	switch authType {
	case authTypeSignedV2, authTypePresignedV2:
		signatureVersion = signV2Algorithm
	case authTypeSigned, authTypePresigned, authTypeStreamingSigned, authTypeStreamingSignedTrailer, authTypePostPolicy:
		signatureVersion = signV4Algorithm
	case authTypeStreamingUnsignedTrailer:
		if isRequestSignatureV4(r) {
			signatureVersion = signV4Algorithm
		}
	}

	var authtype string
	switch authType {
	case authTypePresignedV2, authTypePresigned:
		authtype = "REST-QUERY-STRING"
	case authTypeSignedV2, authTypeSigned, authTypeStreamingSigned, authTypeStreamingSignedTrailer:
		authtype = "REST-HEADER"
	case authTypeStreamingUnsignedTrailer:
		if isRequestSignatureV4(r) {
			authtype = "REST-HEADER"
		}
	case authTypePostPolicy:
		authtype = "POST"
	}

	args := map[string][]string{
		"CurrentTime":      {currTime.Format(time.RFC3339)},
		"EpochTime":        {strconv.FormatInt(currTime.Unix(), 10)},
		"SecureTransport":  {strconv.FormatBool(r.TLS != nil)},
		"SourceIp":         {handlers.GetSourceIPRaw(r)},
		"UserAgent":        {r.UserAgent()},
		"Referer":          {r.Referer()},
		"principaltype":    {principalType},
		"userid":           {username},
		"username":         {username},
		"versionid":        {vid},
		"signatureversion": {signatureVersion},
		"authType":         {authtype},
	}

	if lc != "" {
		args["LocationConstraint"] = []string{lc}
	}

	cloneHeader := r.Header.Clone()
	if age, ok := r.Context().Value(signatureAgeContextKey{}).(string); ok {
		args["signatureAge"] = []string{age}
	}
	cloneHeader.Del("x-amz-signature-age")

	// Tag conditions are filled from typed server state below, never this header.
	cloneHeader.Del(xhttp.AmzObjectTagging)
	if values := r.Header.Values(xhttp.AmzContentSha256); len(values) > 0 {
		args["x-amz-content-sha256"] = values
	}

	for _, objLock := range []string{
		xhttp.AmzObjectLockMode,
		xhttp.AmzObjectLockLegalHold,
		xhttp.AmzObjectLockRetainUntilDate,
	} {
		if values, ok := cloneHeader[objLock]; ok {
			args[strings.TrimPrefix(objLock, "X-Amz-")] = values
		}
		cloneHeader.Del(objLock)
	}

	for key, values := range cloneHeader {
		if strings.EqualFold(key, xhttp.AmzObjectTagging) || reservedConditionInput(key, claims) {
			continue
		}
		if existingValues, found := args[key]; found {
			args[key] = append(existingValues, values...)
		} else {
			args[key] = values
		}
	}

	cloneURLValues := make(url.Values, len(r.Form))
	maps.Copy(cloneURLValues, r.Form)

	for key, values := range cloneURLValues {
		if strings.EqualFold(key, xhttp.AmzObjectTagging) || reservedConditionInput(key, claims) {
			continue
		}
		if existingValues, found := args[key]; found {
			args[key] = append(existingValues, values...)
		} else {
			args[key] = values
		}
	}

	// JWT specific values
	//
	// Add all string claims
	for k, v := range claims {
		if reservedTagCondition(strings.TrimPrefix(k, "ldap")) {
			continue
		}
		vStr, ok := v.(string)
		if ok {
			// Trim any LDAP specific prefix
			args[strings.ToLower(strings.TrimPrefix(k, "ldap"))] = []string{vStr}
		}
	}

	// Add groups claim which could be a list. This will ensure that the claim
	// `jwt:groups` works.
	if grpsVal, ok := claims["groups"]; ok {
		if grpsIs, ok := grpsVal.([]any); ok {
			grps := []string{}
			for _, gI := range grpsIs {
				if g, ok := gI.(string); ok {
					grps = append(grps, g)
				}
			}
			if len(grps) > 0 {
				args["groups"] = grps
			}
		}
	}

	// if not claim groups are available use the one with auth.Credentials
	if _, ok := args["groups"]; !ok {
		if len(groups) > 0 {
			args["groups"] = groups
		}
	}

	tagValues, _ := r.Context().Value(objectTagConditionKey{}).(objectTagConditions)
	for _, input := range []struct {
		namespace string
		value     string
	}{{"ExistingObjectTag", tagValues.existing}, {"RequestObjectTag", tagValues.request}} {
		tagSet, err := tags.ParseObjectTags(input.value)
		if err != nil || tagSet == nil {
			continue
		}
		var keys []string
		for key, value := range tagSet.ToMap() {
			args[input.namespace+"/"+key] = []string{value}
			keys = append(keys, key)
		}
		if input.namespace == "RequestObjectTag" && len(keys) > 0 {
			args["RequestObjectTagKeys"] = keys
		}
	}

	return args
}

// PolicyToBucketAccessPolicy converts a MinIO policy into a minio-go policy data structure.
func PolicyToBucketAccessPolicy(bucketPolicy *policy.BucketPolicy) (*miniogopolicy.BucketAccessPolicy, error) {
	// Return empty BucketAccessPolicy for empty bucket policy.
	if bucketPolicy == nil {
		return &miniogopolicy.BucketAccessPolicy{Version: policy.DefaultVersion}, nil
	}

	data, err := json.Marshal(bucketPolicy)
	if err != nil {
		// This should not happen because bucketPolicy is valid to convert to JSON data.
		return nil, err
	}

	var policyInfo miniogopolicy.BucketAccessPolicy
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	if err = json.Unmarshal(data, &policyInfo); err != nil {
		// This should not happen because data is valid to JSON data.
		return nil, err
	}

	return &policyInfo, nil
}

// BucketAccessPolicyToPolicy - converts minio-go/policy.BucketAccessPolicy to policy.BucketPolicy.
func BucketAccessPolicyToPolicy(policyInfo *miniogopolicy.BucketAccessPolicy) (*policy.BucketPolicy, error) {
	data, err := json.Marshal(policyInfo)
	if err != nil {
		// This should not happen because policyInfo is valid to convert to JSON data.
		return nil, err
	}

	var bucketPolicy policy.BucketPolicy
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	if err = json.Unmarshal(data, &bucketPolicy); err != nil {
		// This should not happen because data is valid to JSON data.
		return nil, err
	}

	return &bucketPolicy, nil
}
