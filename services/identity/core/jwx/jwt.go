package jwx

import (
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm/services/identity/core/environment"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type TokenType string

const (
	TokenTypeAccess             TokenType = "access"
	TokenTypeRefresh            TokenType = "refresh"
	TokenTypeApplicationRequest TokenType = "application_request"
)

var AllTokenType = []TokenType{
	TokenTypeAccess,
	TokenTypeRefresh,
	TokenTypeApplicationRequest,
}

func (e TokenType) IsValid() bool {
	switch e {
	case TokenTypeAccess, TokenTypeRefresh:
		return true
	}
	return false
}

func (e TokenType) String() string {
	return string(e)
}

func CreateToken(tokenType TokenType, userId *string, permissionsSlice []permissions.Permission) string {
	if tokenType != TokenTypeAccess && tokenType != TokenTypeRefresh && tokenType != TokenTypeApplicationRequest {
		tokenType = TokenTypeAccess
	}

	issueTime := time.Now()

	builder := jwt.NewBuilder().
		Claim("typ", tokenType).
		Issuer(os.Getenv(environment.KeysTokenIssuer)).
		Audience([]string{os.Getenv(environment.KeysTokenIssuer)}).
		IssuedAt(issueTime)

	if tokenType == TokenTypeRefresh && userId != nil {
		builder = builder.Expiration(issueTime.Add(time.Hour * 24 * 7)).Subject(*userId)
	} else if tokenType == TokenTypeAccess && userId != nil {
		builder = builder.Expiration(issueTime.Add(time.Minute*15)).
			Subject(*userId).
			Claim("permissions", permissions.BuildPermissionsString(permissionsSlice))
	} else {
		builder = builder.Expiration(issueTime.Add(time.Minute))
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

func ValidateToken(token string) (jwt.Token, *TokenType) {
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

	isValidTokenType := ok2 && (strings.EqualFold(stringTokenType, TokenTypeAccess.String()) ||
		strings.EqualFold(stringTokenType, TokenTypeRefresh.String()) ||
		strings.EqualFold(stringTokenType, TokenTypeApplicationRequest.String()))
	isProperToken := ok && isValidTokenType

	if !isProperToken {
		return nil, nil
	}

	audience, ok := verifiedToken.Get("aud")
	convertedAudience, ok2 := audience.([]string)

	if !slices.Contains(convertedAudience, os.Getenv(environment.KeysTokenIssuer)) {
		return nil, nil
	}

	normalizedTokenType := TokenType(stringTokenType)

	return verifiedToken, &normalizedTokenType
}
