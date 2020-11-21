package auth

import (
	"context"
	"errors"

	"github.com/flyznex/gois"
	kitjwt "github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/endpoint"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type (
	ConfigAuth struct {
		Issuer            string
		Audiences         []string
		IdentityServerURI string
		MethodSignature   string
	}
	Auth struct {
		Validator *gois.JWTValidator
	}
)
type contextKey struct {
	name string
}

// Context keys
var (
	TokenKey             = &contextKey{"Token"}
	IdentityKey          = &contextKey{"Identity"}
	UserIDKey            = &contextKey{"UserID"}
	RolesKey             = &contextKey{"Roles"}
	ErrTokenNotFound     = errors.New("Token not found")
	ErrUnauthorized      = errors.New("Unauthorized")
	ErrRoleUnauthorized  = errors.New("User not authorized")
	ErrScopeUnauthorized = errors.New("Not allowed scope")
)
// NewAuth create new Auth instance
func NewAuth(cfg ConfigAuth) *Auth {
	m := jose.RS256
	if cfg.MethodSignature != "" {
		m = jose.SignatureAlgorithm(cfg.MethodSignature)
	}
	authClient := gois.NewJWKClient(gois.JWKClientOptions{URI: cfg.IdentityServerURI}, nil)
	configuration := gois.NewConfiguration(authClient, cfg.Audiences, cfg.Issuer, m)
	validator := gois.NewValidator(configuration, nil)
	return &Auth{Validator: validator}
}
// AuthenticateGRPCMiddleware middleware validate token user
func (a *Auth) AuthenticateGRPCMiddleware() endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			authorizationToken := ctx.Value(kitjwt.JWTTokenContextKey)
			raw := ""
			if h, ok := authorizationToken.(string); ok {
				raw = h
			}
			if raw == "" {
				return nil, ErrTokenNotFound
			}
			jwtWebToken, err := jwt.ParseSigned(raw)
			if err != nil {
				return nil, err
			}
			if err := a.Validator.ValidateToken(jwtWebToken); err != nil {
				return nil, err
			}
			ctx = context.WithValue(ctx, TokenKey, jwtWebToken)
			claims := map[string]interface{}{}
			err = a.Validator.Claims(jwtWebToken, &claims)
			if err != nil {
				return nil, err
			}
			ctx = context.WithValue(ctx, IdentityKey, claims)
			roles := getRoleFromClaims(claims)
			ctx = context.WithValue(ctx, RolesKey, roles)
			userID, ok := getUserIDFromClaims(claims)
			if !ok {
				return nil, err
			}
			ctx = context.WithValue(ctx, UserIDKey, userID)
			return next(ctx, request)
		}
	}
}
// AuthorizeRole middleware check user's role is allowed with list roles pramaters
func AuthorizeRole(roles ...string) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			r := ctx.Value(RolesKey)
			var rolesMap map[string]string
			if rs, ok := r.(map[string]string); ok {
				rolesMap = rs
			}
			var allow bool = false
			for _, v := range roles {
				if _, ok := rolesMap[v]; ok {
					allow = true
					break
				}
			}
			if !allow {
				return nil, ErrRoleUnauthorized
			}
			return next(ctx, request)
		}
	}
}

// AuthorizeScope middleware check user's scope valid with scope parameter
func AuthorizeScope(scope string) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			c := ctx.Value(IdentityKey)
			claims, ok := c.(map[string]interface{})
			if !ok {
				return nil, ErrUnauthorized
			}
			var allow bool = false
			if scopes, ok := claims["scope"]; ok {
				for _, s := range scopes.([]interface{}) {
					if s.(string) == scope {
						allow = true
						break
					}
				}
			}
			if !allow {
				return nil, ErrScopeUnauthorized
			}
			return next(ctx, request)
		}
	}
}

// internal functions
func getUserIDFromClaims(claims map[string]interface{}) (string, bool) {
	sub, ok := claims["sub"]
	if !ok {
		return "", false
	}
	return sub.(string), ok
}

func getRoleFromClaims(claims map[string]interface{}) map[string]string {
	roles := map[string]string{}
	if rc, ok := claims["role"]; ok {
		switch v := rc.(type) {
		case string:
			roles[v] = v
		case []interface{}:
			for _, r := range v {
				rs := r.(string)
				roles[rs] = rs
			}
		}

	}
	return roles
}
