package validation

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidatePolicy validates a Policy.
func ValidatePolicy(policy *v1.Policy, isPlus bool, enablePreviewPolicies bool) error {
	allErrs := validatePolicySpec(&policy.Spec, field.NewPath("spec"), isPlus, enablePreviewPolicies)
	return allErrs.ToAggregate()
}

func validatePolicySpec(spec *v1.PolicySpec, fieldPath *field.Path, isPlus bool, enablePreviewPolicies bool) field.ErrorList {
	allErrs := field.ErrorList{}

	fieldCount := 0

	if spec.AccessControl != nil {
		allErrs = append(allErrs, validateAccessControl(spec.AccessControl, fieldPath.Child("accessControl"))...)
		fieldCount++
	}

	if spec.RateLimit != nil {
		if !enablePreviewPolicies {
			return append(allErrs, field.Forbidden(fieldPath.Child("rateLimit"),
				"rateLimit is a preview policy. Preview policies must be enabled to use via cli argument -enable-preview-policies"))
		}
		allErrs = append(allErrs, validateRateLimit(spec.RateLimit, fieldPath.Child("rateLimit"), isPlus)...)
		fieldCount++
	}

	if spec.JWTAuth != nil {
		if !enablePreviewPolicies {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("jwt"),
				"jwt is a preview policy. Preview policies must be enabled to use via cli argument -enable-preview-policies"))
		}
		if !isPlus {
			return append(allErrs, field.Forbidden(fieldPath.Child("jwt"), "jwt secrets are only supported in NGINX Plus"))
		}

		allErrs = append(allErrs, validateJWT(spec.JWTAuth, fieldPath.Child("jwt"))...)
		fieldCount++
	}

	if spec.IngressMTLS != nil {
		if !enablePreviewPolicies {
			return append(allErrs, field.Forbidden(fieldPath.Child("ingressMTLS"),
				"ingressMTLS is a preview policy. Preview policies must be enabled to use via cli argument -enable-preview-policies"))
		}
		allErrs = append(allErrs, validateIngressMTLS(spec.IngressMTLS, fieldPath.Child("ingressMTLS"))...)
		fieldCount++
	}

	if spec.EgressMTLS != nil {
		if !enablePreviewPolicies {
			return append(allErrs, field.Forbidden(fieldPath.Child("egressMTLS"),
				"egressMTLS is a preview policy. Preview policies must be enabled to use via cli argument -enable-preview-policies"))
		}
		allErrs = append(allErrs, validateEgressMTLS(spec.EgressMTLS, fieldPath.Child("egressMTLS"))...)
		fieldCount++
	}

	if fieldCount != 1 {
		msg := "must specify exactly one of: `accessControl`, `rateLimit`, `ingressMTLS`, `egressMTLS`"
		if isPlus {
			msg = fmt.Sprint(msg, ", `jwt`")
		}

		allErrs = append(allErrs, field.Invalid(fieldPath, "", msg))
	}

	return allErrs
}

func validateAccessControl(accessControl *v1.AccessControl, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	fieldCount := 0

	if accessControl.Allow != nil {
		for i, ipOrCIDR := range accessControl.Allow {
			allErrs = append(allErrs, validateIPorCIDR(ipOrCIDR, fieldPath.Child("allow").Index(i))...)
		}
		fieldCount++
	}

	if accessControl.Deny != nil {
		for i, ipOrCIDR := range accessControl.Deny {
			allErrs = append(allErrs, validateIPorCIDR(ipOrCIDR, fieldPath.Child("deny").Index(i))...)
		}
		fieldCount++
	}

	if fieldCount != 1 {
		allErrs = append(allErrs, field.Invalid(fieldPath, "", "must specify exactly one of: `allow` or `deny`"))
	}

	return allErrs
}

func validateRateLimit(rateLimit *v1.RateLimit, fieldPath *field.Path, isPlus bool) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateRateLimitZoneSize(rateLimit.ZoneSize, fieldPath.Child("zoneSize"))...)
	allErrs = append(allErrs, validateRate(rateLimit.Rate, fieldPath.Child("rate"))...)
	allErrs = append(allErrs, validateRateLimitKey(rateLimit.Key, fieldPath.Child("key"), isPlus)...)

	if rateLimit.Delay != nil {
		allErrs = append(allErrs, validatePositiveInt(*rateLimit.Delay, fieldPath.Child("delay"))...)
	}

	if rateLimit.Burst != nil {
		allErrs = append(allErrs, validatePositiveInt(*rateLimit.Burst, fieldPath.Child("burst"))...)
	}

	if rateLimit.LogLevel != "" {
		allErrs = append(allErrs, validateRateLimitLogLevel(rateLimit.LogLevel, fieldPath.Child("logLevel"))...)
	}

	if rateLimit.RejectCode != nil {
		if *rateLimit.RejectCode < 400 || *rateLimit.RejectCode > 599 {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("rejectCode"), rateLimit.RejectCode,
				"must be within the range [400-599]"))
		}
	}

	return allErrs
}

func validateJWT(jwt *v1.JWTAuth, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateJWTRealm(jwt.Realm, fieldPath.Child("realm"))...)

	if jwt.Secret == "" {
		return append(allErrs, field.Required(fieldPath.Child("secret"), ""))
	}
	allErrs = append(allErrs, validateSecretName(jwt.Secret, fieldPath.Child("secret"))...)

	allErrs = append(allErrs, validateJWTToken(jwt.Token, fieldPath.Child("token"))...)

	return allErrs
}

func validateIngressMTLS(ingressMTLS *v1.IngressMTLS, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if ingressMTLS.ClientCertSecret == "" {
		return append(allErrs, field.Required(fieldPath.Child("clientCertSecret"), ""))
	}
	allErrs = append(allErrs, validateSecretName(ingressMTLS.ClientCertSecret, fieldPath.Child("clientCertSecret"))...)

	allErrs = append(allErrs, validateIngressMTLSVerifyClient(ingressMTLS.VerifyClient, fieldPath.Child("verifyClient"))...)

	if ingressMTLS.VerifyDepth != nil {
		allErrs = append(allErrs, validatePositiveIntOrZero(*ingressMTLS.VerifyDepth, fieldPath.Child("verifyDepth"))...)
	}
	return allErrs
}

func validateEgressMTLS(egressMTLS *v1.EgressMTLS, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateSecretName(egressMTLS.TLSSecret, fieldPath.Child("tlsSecret"))...)

	if egressMTLS.VerifyServer && egressMTLS.TrustedCertSecret == "" {
		return append(allErrs, field.Required(fieldPath.Child("trustedCertSecret"), "must be set when verifyServer is 'true'"))
	}
	allErrs = append(allErrs, validateSecretName(egressMTLS.TrustedCertSecret, fieldPath.Child("trustedCertSecret"))...)

	if egressMTLS.VerifyDepth != nil {
		allErrs = append(allErrs, validatePositiveIntOrZero(*egressMTLS.VerifyDepth, fieldPath.Child("verifyDepth"))...)
	}

	allErrs = append(allErrs, validateSSLName(egressMTLS.SSLName, fieldPath.Child("sslName"))...)

	return allErrs
}

func validateSSLName(name string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if name != "" {
		for _, msg := range validation.IsDNS1123Subdomain(name) {
			allErrs = append(allErrs, field.Invalid(fieldPath, name, msg))
		}
	}
	return allErrs
}

var validateVerifyClientKeyParameters = map[string]bool{
	"on":             true,
	"off":            true,
	"optional":       true,
	"optional_no_ca": true,
}

func validateIngressMTLSVerifyClient(verifyClient string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if verifyClient != "" {
		allErrs = append(allErrs, validateParameter(verifyClient, validateVerifyClientKeyParameters, fieldPath)...)
	}
	return allErrs
}

const rateFmt = `[1-9]\d*r/[sSmM]`
const rateErrMsg = "must consist of numeric characters followed by a valid rate suffix. 'r/s|r/m"

var rateRegexp = regexp.MustCompile("^" + rateFmt + "$")

func validateRate(rate string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if rate == "" {
		return append(allErrs, field.Required(fieldPath, ""))
	}

	if !rateRegexp.MatchString(rate) {
		msg := validation.RegexError(rateErrMsg, rateFmt, "16r/s", "32r/m", "64r/s")
		return append(allErrs, field.Invalid(fieldPath, rate, msg))
	}
	return allErrs
}

func validateRateLimitZoneSize(zoneSize string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if zoneSize == "" {
		return append(allErrs, field.Required(fieldPath, ""))
	}

	allErrs = append(allErrs, validateSize(zoneSize, fieldPath)...)

	kbZoneSize := strings.TrimSuffix(strings.ToLower(zoneSize), "k")
	kbZoneSizeNum, err := strconv.Atoi(kbZoneSize)

	mbZoneSize := strings.TrimSuffix(strings.ToLower(zoneSize), "m")
	mbZoneSizeNum, mbErr := strconv.Atoi(mbZoneSize)

	if err == nil && kbZoneSizeNum < 32 || mbErr == nil && mbZoneSizeNum == 0 {
		allErrs = append(allErrs, field.Invalid(fieldPath, zoneSize, "must be greater than 31k"))
	}

	return allErrs
}

var rateLimitKeySpecialVariables = []string{"arg_", "http_", "cookie_"}

// rateLimitKeyVariables includes NGINX variables allowed to be used in a rateLimit policy key.
var rateLimitKeyVariables = map[string]bool{
	"binary_remote_addr": true,
	"request_uri":        true,
	"uri":                true,
	"args":               true,
}

func validateRateLimitKey(key string, fieldPath *field.Path, isPlus bool) field.ErrorList {
	allErrs := field.ErrorList{}

	if key == "" {
		return append(allErrs, field.Required(fieldPath, ""))
	}

	if !escapedStringsFmtRegexp.MatchString(key) {
		msg := validation.RegexError(escapedStringsErrMsg, escapedStringsFmt, `Hello World! \n`, `\"${request_uri}\" is unavailable. \n`)
		allErrs = append(allErrs, field.Invalid(fieldPath, key, msg))
	}

	allErrs = append(allErrs, validateStringWithVariables(key, fieldPath, rateLimitKeySpecialVariables, rateLimitKeyVariables, isPlus)...)

	return allErrs
}

var jwtTokenSpecialVariables = []string{"arg_", "http_", "cookie_"}

func validateJWTToken(token string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if token == "" {
		return allErrs
	}

	nginxVars := strings.Split(token, "$")
	if len(nginxVars) != 2 {
		return append(allErrs, field.Invalid(fieldPath, token, "must have 1 var"))
	}
	nVar := token[1:]

	special := false
	for _, specialVar := range jwtTokenSpecialVariables {
		if strings.HasPrefix(nVar, specialVar) {
			special = true
			break
		}
	}

	if special {
		// validateJWTToken is called only when NGINX Plus is running
		isPlus := true
		allErrs = append(allErrs, validateSpecialVariable(nVar, fieldPath, isPlus)...)
	} else {
		return append(allErrs, field.Invalid(fieldPath, token, "must only have special vars"))
	}

	return allErrs
}

var validLogLevels = map[string]bool{
	"info":   true,
	"notice": true,
	"warn":   true,
	"error":  true,
}

func validateRateLimitLogLevel(logLevel string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if !validLogLevels[logLevel] {
		allErrs = append(allErrs, field.Invalid(fieldPath, logLevel, fmt.Sprintf("Accepted values: %s",
			mapToPrettyString(validLogLevels))))
	}

	return allErrs
}

const jwtRealmFmt = `([^"$\\]|\\[^$])*`
const jwtRealmFmtErrMsg string = `a valid realm must have all '"' escaped and must not contain any '$' or end with an unescaped '\'`

var jwtRealmFmtRegexp = regexp.MustCompile("^" + jwtRealmFmt + "$")

func validateJWTRealm(realm string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if realm == "" {
		return append(allErrs, field.Required(fieldPath, ""))
	}

	if !jwtRealmFmtRegexp.MatchString(realm) {
		msg := validation.RegexError(jwtRealmFmtErrMsg, jwtRealmFmt, "MyAPI", "My Product API")
		allErrs = append(allErrs, field.Invalid(fieldPath, realm, msg))
	}

	return allErrs
}

func validateIPorCIDR(ipOrCIDR string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	_, _, err := net.ParseCIDR(ipOrCIDR)
	if err == nil {
		// valid CIDR
		return allErrs
	}

	ip := net.ParseIP(ipOrCIDR)
	if ip != nil {
		// valid IP
		return allErrs
	}

	return append(allErrs, field.Invalid(fieldPath, ipOrCIDR, "must be a CIDR or IP"))
}

func validatePositiveInt(n int, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if n <= 0 {
		return append(allErrs, field.Invalid(fieldPath, n, "must be positive"))
	}

	return allErrs
}
