package security

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ParseUnverifiedJWT parses JWT and returns its claims
// but DOES NOT verify the signature.
//
// It verifies only the exp, iat and nbf claims.
func ParseUnverifiedJWT(token string) (jwt.MapClaims, error) {
	return ParseUnverifiedJWTWithLeeway(token, 0)
}

// ParseUnverifiedJWTWithLeeway is the same as [ParseUnverifiedJWT]
// but allows specifying a clock skew leeway for the exp, iat and nbf checks.
func ParseUnverifiedJWTWithLeeway(token string, leeway time.Duration) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	parser := &jwt.Parser{}
	_, _, err := parser.ParseUnverified(token, claims)

	if err == nil {
		validatorOpts := []jwt.ParserOption{jwt.WithIssuedAt()}
		if leeway > 0 {
			validatorOpts = append(validatorOpts, jwt.WithLeeway(leeway))
		}
		err = jwt.NewValidator(validatorOpts...).Validate(claims)
	}

	return claims, err
}

// ParseJWT verifies and parses JWT and returns its claims.
func ParseJWT(token string, verificationKey string) (jwt.MapClaims, error) {
	return ParseJWTWithLeeway(token, verificationKey, 0)
}

// ParseJWTWithLeeway is the same as [ParseJWT] but allows specifying
// a clock skew leeway to tolerate when validating the "exp", "nbf"
// and "iat" registered claims.
//
// This is usually used with short-lived tokens (eg. signed file download
// URLs) where minor clock differences between the issuing and the
// verifying server could result in false-negative validations.
func ParseJWTWithLeeway(token string, verificationKey string, leeway time.Duration) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithLeeway(leeway),
	)

	parsedToken, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte(verificationKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		return claims, nil
	}

	return nil, errors.New("unable to parse token")
}

// NewJWT generates and returns new HS256 signed JWT.
func NewJWT(payload jwt.MapClaims, signingKey string, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		// @todo consider with the refactoring to either remove the
		// duration argument or make it always take precedence?
		"exp": time.Now().Add(duration).Unix(),
	}

	for k, v := range payload {
		claims[k] = v
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(signingKey))
}
