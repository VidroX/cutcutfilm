package jwx

import (
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm-shared/tokens"
	"github.com/VidroX/cutcutfilm/services/identity/core/environment"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type DurationWrapper struct {
	time.Duration
}

type TokenParams struct {
	TokenType   tokens.TokenType
	UserId      *string
	Permissions []permissions.Permission
	ExpiryTime  *DurationWrapper
	AddAudience bool
}

func CreateToken(params *TokenParams) string {
	issueTime := time.Now()

	builder := jwt.NewBuilder().
		Claim("typ", params.TokenType).
		Issuer(os.Getenv(environment.KeysTokenIssuer)).
		IssuedAt(issueTime)

	if params.AddAudience {
		builder = builder.Audience([]string{os.Getenv(environment.KeysTokenIssuer)})
	}

	if params.ExpiryTime != nil {
		builder = builder.Expiration(issueTime.Add(params.ExpiryTime.Duration))
	} else if params.TokenType == tokens.TokenTypeRefresh {
		builder = builder.Expiration(issueTime.Add(time.Hour * 24 * 7))
	} else if params.TokenType == tokens.TokenTypeAccess {
		builder = builder.Expiration(issueTime.Add(time.Minute * 15))
	}

	if params.TokenType == tokens.TokenTypeRefresh || params.TokenType == tokens.TokenTypeAccess {
		builder = builder.Subject(*params.UserId)
	}

	if len(params.Permissions) > 0 {
		builder = builder.Claim("permissions", permissions.BuildPermissionsString(params.Permissions))
	}

	tok, err := builder.Build()

	if err != nil {
		log.Printf("Failed to build token: %s\n", err)
		return ""
	}

	var rawPrivateKey interface{}
	var privateKey = CutcutfilmKeys.PrivateKey

	if privateKey == nil {
		log.Println("Failed to retrieve Private Key")

		return ""
	}

	_ = (*privateKey).Raw(&rawPrivateKey)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES512, rawPrivateKey))

	if err != nil {
		log.Printf("Failed to sign token: %s\n", err)
		return ""
	}

	return string(signed)
}

func ValidateToken(token string) (jwt.Token, *tokens.TokenType) {
	var rawPublicKey interface{}
	var publicKey = CutcutfilmKeys.PublicKey

	if publicKey == nil {
		log.Println("Failed to retrieve Public Key")

		return nil, nil
	}

	_ = (*publicKey).Raw(&rawPublicKey)

	normalizedToken := strings.TrimSpace(strings.TrimPrefix(token, "Bearer"))

	verifiedToken, err := jwt.Parse([]byte(normalizedToken), jwt.WithKey(jwa.ES512, rawPublicKey))
	if err != nil {
		if os.Getenv(environment.KeysDebug) == "True" {
			log.Printf("Failed to verify JWS (%s): %s\n", normalizedToken, err)
		}
		return nil, nil
	}

	tokenType, ok := verifiedToken.Get("typ")
	stringTokenType, ok2 := tokenType.(string)

	isValidTokenType := ok2 && (strings.EqualFold(stringTokenType, tokens.TokenTypeAccess.String()) ||
		strings.EqualFold(stringTokenType, tokens.TokenTypeRefresh.String()) ||
		strings.EqualFold(stringTokenType, tokens.TokenTypeApplicationRequest.String()))
	isProperToken := ok && isValidTokenType

	if !isProperToken {
		return nil, nil
	}

	audience, ok := verifiedToken.Get("aud")
	convertedAudience, ok2 := audience.([]string)

	if !slices.Contains(convertedAudience, os.Getenv(environment.KeysTokenIssuer)) {
		return nil, nil
	}

	normalizedTokenType := tokens.TokenType(stringTokenType)

	return verifiedToken, &normalizedTokenType
}
