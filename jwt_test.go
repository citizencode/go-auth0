package jwt

import (
	"strings"
	"testing"
)

const expiredJwks = `{
	"keys": [
	  {
		"alg": "RS256",
		"kty": "RSA",
		"use": "sig",
		"n": "sPCieGF_WzQdh5wrRp9haSpprTjv_U_-jgko1DS9WxCG6O37q-S4O0Pl2tlTbtMNbeWO0nFuzXLmoMvCsVxgaqVLJxaTnPrJyqdfAyBefkXm_UooNJkPlqLtDdnK4OTUhCt1DJsO5-nnpZBvVONjISeEf19bh6JaT6q82RQLMtq_UGfjhsJZ-geQoPTym9fjnaSZocAyNZxcwmtzcqCPAygVPJRRdgql-xPH2XV0KW16CO25VneWijetYEycZ_dRdT6JhazsBx9IA4-hIu1auBBDoEYrWASNrqoENKKr_IWxKVUnQSKahVfrl6j2oheoeZ1_4_tHGgfhqSwtTlzr7Q",
		"e": "AQAB",
		"kid": "34bvZ7Ue6A5bghOEvfZjD",
		"x5t": "dMWGvcBlWkpcZYIJiGmKV4HN4rE",
		"x5c": [
		  "MIIDCzCCAfOgAwIBAgIJULBZmf6GhwWpMA0GCSqGSIb3DQEBCwUAMCMxITAfBgNVBAMTGGNpdGl6ZW5jb2RlLmV1LmF1dGgwLmNvbTAeFw0yMTA4MTExNTIyMzdaFw0zNTA0MjAxNTIyMzdaMCMxITAfBgNVBAMTGGNpdGl6ZW5jb2RlLmV1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDwonhhf1s0HYecK0afYWkqaa047/1P/o4JKNQ0vVsQhujt+6vkuDtD5drZU27TDW3ljtJxbs1y5qDLwrFcYGqlSycWk5z6ycqnXwMgXn5F5v1KKDSZD5ai7Q3ZyuDk1IQrdQybDufp56WQb1TjYyEnhH9fW4eiWk+qvNkUCzLav1Bn44bCWfoHkKD08pvX452kmaHAMjWcXMJrc3KgjwMoFTyUUXYKpfsTx9l1dCltegjtuVZ3loo3rWBMnGf3UXU+iYWs7AcfSAOPoSLtWrgQQ6BGK1gEja6qBDSiq/yFsSlVJ0EimoVX65eo9qIXqHmdf+P7RxoH4aksLU5c6+0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUN6fKejt8WnZ1/t4mQgv6Oiwss6QwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQANA+bfjMHbS3kCR08rOlsJb7XEBd2gkUAqpJEQe2VRo93I0HwHqUDfEY+/XEBqNrUzgQowsLO77zpbXNKXMG0B9y6N4V7sWhZwgAaI+V28YjyamApDbg0xgOLQwUp46KDXRcUoHOnEirJ4yD8MQap4uq2dBrlYiQ4uS2XbK9eMmxyB1RcOBNgvwZrowAzUBpAg+Tmb0rCwDgLB0iORaC8xsIZo1lG0vb3GxeCU0SNSByy62Orgkf4uRxgrk1bL8PT65/Uy35a2+9SiltNrS7/BW22BfOw2FeKUyjd0JZZVMhtGEaPCaIiki26JyBE1ZCsr2U4A/XWrQ/NBk4hp4LTk"
		]
	  },
	  {
		"alg": "RS256",
		"kty": "RSA",
		"use": "sig",
		"n": "t1TSYUr0rgJaK3iNx2PRy2G3RUCdi4q3O-dThuHyVaRpm25MEDpAtj9iGRBxyEM7FGkSJKUa0mt6GgUBewaxWcZkq1BmZm-C_bMZUxU0xieX500ffdJYKFFZOPwqCfrh60zYLz-PklGqNnPVLdfsDwcycdMMBw8Kt0gu3ZL1uSq0HPHF-cMjT0HSvaf1nR-Dp1gCjIrqJr0nLGT7nvOeDSGJVdEXRKW8LU97jhm-aQ9Y8-ipra9jy8HpPafgcVYgci8oO0oW9INBcZKxKzzFke4TpYEhgewEa00WNeJan1cU8KIec4xlkV_W8QRPnSjlkXKGWC5A2F4fYDH-WP1L6w",
		"e": "AQAB",
		"kid": "Fe4ftDR2jWnhS9Hej0PY7",
		"x5t": "j975wu1N_hFpWvrg-mbUXYlvOrc",
		"x5c": [
		  "MIIDCzCCAfOgAwIBAgIJFMZW3i8zVfrVMA0GCSqGSIb3DQEBCwUAMCMxITAfBgNVBAMTGGNpdGl6ZW5jb2RlLmV1LmF1dGgwLmNvbTAeFw0yMTA4MTExNTIyMzdaFw0zNTA0MjAxNTIyMzdaMCMxITAfBgNVBAMTGGNpdGl6ZW5jb2RlLmV1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALdU0mFK9K4CWit4jcdj0ctht0VAnYuKtzvnU4bh8lWkaZtuTBA6QLY/YhkQcchDOxRpEiSlGtJrehoFAXsGsVnGZKtQZmZvgv2zGVMVNMYnl+dNH33SWChRWTj8Kgn64etM2C8/j5JRqjZz1S3X7A8HMnHTDAcPCrdILt2S9bkqtBzxxfnDI09B0r2n9Z0fg6dYAoyK6ia9Jyxk+57zng0hiVXRF0SlvC1Pe44ZvmkPWPPoqa2vY8vB6T2n4HFWIHIvKDtKFvSDQXGSsSs8xZHuE6WBIYHsBGtNFjXiWp9XFPCiHnOMZZFf1vEET50o5ZFyhlguQNheH2Ax/lj9S+sCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUUTlQbgGNK0tDCxNU3EQGFmpUa7YwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQAYNUYzUYtE29es+JiqAFbUz2W/LJbKi2zy/TuFsREQZLaPriopZ9IXzHnirJbvQMSUaisJPmLw7pXONSDrucIOxfkYzMtmvxtI+ZAODzXic0WFmGKZWmepZF1PWaKbfaVmO5kNp7XGLOLyQ2ZJWBE1aQ8S0Mx1DSjlQXJ+FHy8rHAwwijbuDbmO9LfPYlOsMrBOYQdT5k9Kt1aF/Qp3aWHwRR/K0A1O0OMJR2RfV0lgiOwW4GoVr5LtmW6Z8MQ/dPryF4C6xne93Ucwz5SUfa/ck/7Fp+IJw5MWOQNDc3/e6mefdo//vWI2ZUubJ4b8/7vCx30gJvkdFcbrUmEDTvV"
		]
	  }
	]
  }`

const expiredJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjM0YnZaN1VlNkE1YmdoT0V2ZlpqRCJ9.eyJpc3MiOiJodHRwczovL2NpdGl6ZW5jb2RlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiJnb29nbGUtb2F1dGgyfDEwOTc5NzM2MzEzNjQ0MjAzODk3MSIsImF1ZCI6WyJkZXYtZGFzaGJvYXJkLWJhY2tlbmQiLCJodHRwczovL2NpdGl6ZW5jb2RlLmV1LmF1dGgwLmNvbS91c2VyaW5mbyJdLCJpYXQiOjE2Mjk3MjUxMzAsImV4cCI6MTYyOTgxMTUzMCwiYXpwIjoieTEzTDRLWVdMQUwxVHJieHFaeHVFN0tBaWFaaTc2SUwiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIn0.dRaD-DlYRwg5bYTiVd5UMBog1E1IBEwK6-_73p6E6B6TsVqZU8zAQnlQVvhtZYmHRsL5SxU474JSEL6LbSg1m2CuUR1d7aYFTLt0nassHC6z8JiaA1_gkrmlYJL3e9kLhzJqM2EnHOsx-wvY4udMc_4wJQQcR6Xhuoz6kejskvcZt3y0fs0Qo9KNFc47HIEVchRZd5d1MVC8i6qj7k3Fn5BIJdaRp8VFq5yWbhEBX_wJOFMewi_vXhyXZPVHBrB2K-jZATKU7_TuantGED868BafPUTbosd6fBTfSpZyFkz5Gpc8SIh3vjKpb0H-x4yTaOYF1dRm_lgvKoYGMmV51Q"

func TestJwt(t *testing.T) {
	expectedErr := "Token is expired"
	jwks, err := parseJwks([]byte(expiredJwks))
	if err != nil {
		t.Fatalf("Unexpectedly failed to parse jwks, %v", err)
	}
	r := RS256{jwks}
	_, err = r.JWT(expiredJwt)
	if !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("Expected expired token, got, %v", err)
	}
}
