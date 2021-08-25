package jwt

import (
	"strings"
	"testing"
)

// expires 2031
const validJwks = `{
	"keys": [
		{
		"alg": "RS256",
		"kty": "RSA",
		"use": "sig",
		"kid": "1",
		"x5c": ["MIIE2DCCAsACCQCqonZfu3tmvzANBgkqhkiG9w0BAQsFADAuMQswCQYDVQQGEwJaQTEfMB0GA1UEAwwWYXV0aDAuY2l0aXplbmNvZGUudGVzdDAeFw0yMTA4MjUxMDMzNThaFw0zMTA4MjMxMDMzNThaMC4xCzAJBgNVBAYTAlpBMR8wHQYDVQQDDBZhdXRoMC5jaXRpemVuY29kZS50ZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtwWIFXNW2EYupuzwqh7tR3z6GbTheGOnxTDyb9c6AP+4qHIFSx3YcazX3V2eBrIi2DjVN5uSSJ5jgVu6fTcJez5e7wuRZw90WF24Vf0iigHblEvDZk4DIXISCicMZ1Z0Ji2BlMmgDXgskBfRPYyFNWTLYxze9FtZqosPJcr71T9R2pRH8beUQ3v/3YvavgEOqrNFYUhdpjemGnahyjS3jKwGZmOAG0dWJamRwy+dLneXwAE/wZV/pCXalG/dbDLDR4GBswlNXbID8lynk+DxbBmRd15KxSaE8CWUCehKJCj84GECszFphBDxtM5+nfRtM2yqMdZhmBbjGVaOdrjFZ2wOcObiD912xP+a9tHukHKZYhHuGQ8UoXzFGwxKcDL3zvlfric8bBwRgjzgXvksFe76TQCT1dZHwhfA/4NNgcooov6A3OsrTHfZVDebUyF4yjWrPHB6Pl/nxl13Tc5tsen9ol8OKj0xkPIbbFiPJJudZiePRyTZswqJmfKEUiiTm7uIu5/RbsbSOCwEzV/FhQnNUtEtTiq9Ljx8g6dMOuv+90YvQpws5S02Bs/Np9lMV3c8oKufwGQHlCPd9oemGBti114y2FhhmxGPGDEkOaWHJ48wC35NXAdnAzNBzKscE0jtEp/Mx9XfC9XDsZ17fJzmnkVulB+RuLNqqFVyFwUCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAFzpR+znsrWVs4Ts/IZ9vPHWozKzrsIbJN4nSzN59iBcOxMoFFuNoanVNj2/f7awFGJavt4Png4ngnMvW4Jmz5sMlBwhMpUGxoVTf0zXlUzoKO9G7bvStj28gZkK7WB3deAqEayar9H5GLUH4zq2NJNEImn0Dmb/6UK5XwymnxBQeUlFPnqbdDNwS+P5FNnnX2jF4BFtA3dQP5T/s0hS+w8v4VN6rsHQWhLJh4MzdaUPqa6JDjrk+OH4tDt+8ddW1krVH/JWA5mHRMXKt1B1PoeI8bZbuEX64q4nIoVR+15Tg7QF5ZMhC16go162sTkAOQtvNgdUGhkRGAAT6zgWBlg1oWu1rcoXfhXoOw4jd3XV30FbqcpZPHEkoIcloIh14P5VEm2RvyQ0pFWR0+RbQRY6/pdklQb7q5I9URQunxB5ZsUlaUae2cfxQFgTlAn7IX1fZ9C7vmGjbGNRJAgKmjm5cztkLc5v8e63R/Ea9cPguh0uuu0IBBUzv2YKHr79xKEI+MU10R7WSDLeV9GOwH2XRM+hUdyiDY1TrcHkMB0+A0leAO9Gqg+24nWKLz6xHu+/tkufV3+BzmBih0BxKmOl/oLgcSPCiGG3LnkFtKVN4MfqxMlDrddjNNCw9/uOuuYuI0PpWgYkd7R+WoNpBruXGRg+6m0L6CrpcIVfBQ+s="]
		}
	]
}`

const validJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOmZhbHNlLCJpYXQiOjE2Mjk4OTAyOTUsImV4cCI6MjAwMDAwMDAwMH0.fRWYZIPmkWkTkfypx7yyVSASiXYCuXcRJoCEho881D2VT7wSmI5lp4EylE1A-AN9c0TKa5QJId8Iv1E3SUqDB7ri9a4ejGmgBv8vKOHL3Ou329BCIHrojKsgvitPhI-4CHM7SSN-ZKMQqJ3u-bWAEURlC938if4-Sbi4BCu_027dG8C077odErT42XbCOuH1gWjll7h2_Vng8Z26i4W31M3NH2hluxi5X1JGHJe4FB0J-C5xx_usWES9n9Kwp4ygvgWJqL_wzqewxdYh4dXn0nMORDDpytgNWamtu_5Q-o5p-_xLI-IEyqgx5DiMm_u-SufUCWxHqPono7fI1fe_Gxvv79_DV7Je-1T-zWTmJaDyTgiY6sTDKdS1qx2YUT-zVCEksy-Nn3Z9_FqHuOJSjT525L5Qbr_Y20XvUQuEjLquESMrmUNdzEL-A-83_q-4QOLm4Gg3zvSwekpKHvVivnivp2FIHTlp7BLsxUMxfw3a50jyV6wtno5OYvRkwVdx_uakoE8YE_XwG_4-fQQdUJBJG6ZXYehyVvRfa3GIERXouOAQZHEr0Jkzn6iL1_WOJrzpagl-5m2q_cXaJ2U4HtQnx5y06wjP3107kyxObm_3Fra8ujbMqexrDD17Cq8NwkUWOt411m-EOpb1BNwUeEJ9gtfhACV6yvRu-SJif6s"
const incorrectAlgJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6IjEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOmZhbHNlLCJpYXQiOjE2Mjk4OTAyOTUsImV4cCI6MjAwMDAwMDAwMH0.nINKtmErXQfJ_JKaicrigIYGRzDDJqPVfOfN4QA_oV_diJkOfnW3kMmm1Py1JmxqFFBaxiRHOA82SIDWToMYzPS2HDzJ7u4PEWRI_1bc-5hdFg8BRuheP3M9lwZw1DZ5MId9-26q_XCt2MTbXkDnXvUzf5PUOwJ21i4tE2430CykCEWR6nDkxDyGCqs3DsjiKfwEirV89CpLc773SwNEuuFN-FoHacPm0vO5EovSNKC64BQIPk352biugj-3wAL7hGe5kr4VkQZBWOgqG-agQf-QLFJFO9lQUC0VRB0x8-_hS2wTAG3ZKfYtm9gS7IGQScoLmOfM_Vx89u9GVd3ar06Gssky6fJ7BjdYqlRea7ybptS-xgyfEDOBNDIfimvpCP656DY9qNakSWeAEMkngnKNgDqazbSf4rPVufQa1PW0F3AVR6z2QHcEeZell0WcF6TYJ06JzwRqkcQtY_V9twJc5wflqq4agTrI0exs5sVRPxCfAHeO-PipxsfVIdTYhVMkNICshoRx9h4GJ_H7vj7SmvbcE8hdqJaxmdpGpOGEAiqEDGab9fdZXQ6uIf-WN_2ByGlWHqoxfMJcqb0YvtdvIPRfnBC8aQ0jUXowRBrjtPHP4da9RRNo-MKYsoBKWiZR5DzkP8LT26q6CBh1W0xe4DuYSQGbXOfiI2127Jo"

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
const invalidSignatureJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOmZhbHNlLCJpYXQiOjE2Mjk4OTAyOTUsImV4cCI6MjAwMDAwMDAwMH0.WTmuZ7O4lMs7sQ2rdMO3lTLdLv5DwAe9Mw6Rp5yyuDP8PUgM-n9EIUAbm15LaABgatnhFldaWJHW_JLJa7wUKMCD93J_g5AJJJwlgWH2nbo7Gp3UqWcarpbRsg1rnA7P0nPw3JHE4eKZN0a78JTj3hWITrT-ytH5chv0hX29RkMjQsuJ2fGkrg9cOkKrHA1owlK0idlyMN_-kzOFq4Oi8wcVU1tYJW61Tdf29dWOMXfKbe4YhtN9qivE6ZAsoIUQcVzlRMqHE0CKQDyoTYpOsba1-AFt_ZN6P3KlKBew68orq-1H0YAWu_YAt_uB7JfNJmQrAdDPox04ibAvcCMm4VOdZ_1oftVdRjPDdrEY4t2_VVDKJ5Jw62wpb1XcfFiNkt4npJGObiEIR9RtR9ei8T2T9C6o_MNUGzmorMnEbcZ_5K4TKgCU_fpoVz71AIXfeBzBq0OFlXP7ytKE9rS9xlvCYLQsKGLydmL-Djsm6SBTlc2XUbndHasPY-aUikB1AKq1LIdavuwuDXg9ngaXP6F3-pk8Dykfou0AD27SqOD3JO666eAPnKyXCScztl3dVTn8InThNFj0E639pFO2U2sh-7L7MYEPaNRhlurXrzT57biqPlFGelLMDjc7faS4-cuvAVQ5LNufCg5eHaxsEBReRSAIaDZoZQFDCFEDipQ"

func TestJwt(t *testing.T) {
	tcs := []struct {
		desc        string
		jwt         string
		jwks        string
		expectedErr string
	}{
		{
			desc:        "expired jwt",
			jwks:        expiredJwks,
			jwt:         expiredJwt,
			expectedErr: "Token is expired",
		},
		{
			desc:        "valid jwt",
			jwt:         validJwt,
			jwks:        validJwks,
			expectedErr: "",
		},
		{
			desc:        "incorrect alg",
			jwks:        validJwks,
			jwt:         incorrectAlgJwt,
			expectedErr: "incorrect Alg",
		},
		{
			desc:        "could not find key",
			jwks:        expiredJwks,
			jwt:         validJwt,
			expectedErr: "could not find key",
		},
		{
			desc:        "invalid signature",
			jwks:        validJwks,
			jwt:         invalidSignatureJwt,
			expectedErr: "verification error",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			jwks, err := parseJwks([]byte(tc.jwks))
			if err != nil {
				t.Fatalf("Unexpectedly failed to parse jwks, %v", err)
			}
			r := RS256{jwks}
			_, err = r.JWT(tc.jwt)
			if tc.expectedErr == "" {
				if err != nil {
					t.Errorf("Unexpected error, %v", err)
				}
			} else {
				if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Errorf("Expected error to contain %q got, %v", tc.expectedErr, err)
				}
			}
		})
	}
}
