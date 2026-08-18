package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

var allowedTrustedPoolScopes = map[string]struct{}{
	"credential:ack":     {},
	"seat:provision":     {},
	"seat:read":          {},
	"seat:write":         {},
	"settlement:resolve": {},
}

type clientProvisionOptions struct {
	ClientID       string
	ExternalPoolID string
	Scopes         []string
	ExpiresAt      *time.Time
	ClearExpiry    bool
	Rotate         bool
}

type clientCredentials struct {
	BearerSecret string
	HMACSecret   string
}

func main() {
	clientID := flag.String("client-id", "", "integration client ID")
	externalPoolID := flag.String("external-pool-id", "", "the only external pool this client may access")
	scopeCSV := flag.String("scopes", "", "comma-separated trusted-pool scopes")
	expiresAtText := flag.String("expires-at", "", "optional RFC3339 credential expiry")
	clearExpiry := flag.Bool("clear-expiry", false, "remove an existing client's expiry during rotation")
	rotate := flag.Bool("rotate", false, "replace an existing client's credentials; also required to bind a disabled legacy client")
	flag.Parse()

	dsn := firstNonEmpty(os.Getenv("DATABASE_DSN"), os.Getenv("DATABASE_URL"))
	if dsn == "" {
		log.Fatal("DATABASE_DSN or DATABASE_URL is required")
	}
	key, err := decodeEncryptionKey(os.Getenv("TOTP_ENCRYPTION_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	scopes, err := parseScopes(*scopeCSV)
	if err != nil {
		log.Fatal(err)
	}
	var expiresAt *time.Time
	if strings.TrimSpace(*expiresAtText) != "" {
		parsed, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(*expiresAtText))
		if parseErr != nil {
			log.Fatalf("invalid -expires-at: %v", parseErr)
		}
		expiresAt = &parsed
	}
	if *clearExpiry && expiresAt != nil {
		log.Fatal("-clear-expiry and -expires-at are mutually exclusive")
	}
	if *clearExpiry && !*rotate {
		log.Fatal("-clear-expiry requires -rotate")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		log.Fatalf("connect database: %v", err)
	}
	credentials, err := provisionTrustedPoolClient(ctx, db, key, rand.Reader, clientProvisionOptions{
		ClientID: *clientID, ExternalPoolID: *externalPoolID, Scopes: scopes,
		ExpiresAt: expiresAt, ClearExpiry: *clearExpiry, Rotate: *rotate,
	})
	if err != nil {
		log.Fatal(err)
	}
	// The generated credentials are deliberately returned once and never logged
	// by the server. Redirect stdout directly into the target secret store.
	if _, err = fmt.Fprintf(os.Stdout, "client_id=%s\nbearer_secret=%s\nhmac_secret=%s\n",
		strings.TrimSpace(*clientID), credentials.BearerSecret, credentials.HMACSecret); err != nil {
		log.Fatalf("write generated credentials: %v", err)
	}
}

func provisionTrustedPoolClient(
	ctx context.Context,
	db *sql.DB,
	encryptionKey []byte,
	random io.Reader,
	options clientProvisionOptions,
) (clientCredentials, error) {
	options.ClientID = strings.TrimSpace(options.ClientID)
	options.ExternalPoolID = strings.TrimSpace(options.ExternalPoolID)
	if db == nil || options.ClientID == "" || len(options.ClientID) > 64 ||
		options.ExternalPoolID == "" || len(options.ExternalPoolID) > 128 {
		return clientCredentials{}, errors.New("client-id and external-pool-id are required and must fit database limits")
	}
	if len(options.Scopes) == 0 {
		return clientCredentials{}, errors.New("at least one trusted-pool scope is required")
	}
	if options.ClearExpiry && options.ExpiresAt != nil {
		return clientCredentials{}, errors.New("clear-expiry and expires-at are mutually exclusive")
	}
	if options.ClearExpiry && !options.Rotate {
		return clientCredentials{}, errors.New("clear-expiry requires rotation")
	}
	if options.ExpiresAt != nil && !options.ExpiresAt.After(time.Now()) {
		return clientCredentials{}, errors.New("expires-at must be in the future")
	}
	if len(encryptionKey) != 32 {
		return clientCredentials{}, errors.New("TOTP_ENCRYPTION_KEY must decode to exactly 32 bytes")
	}
	bearerSecret, err := generateCredential(random, "tpb_")
	if err != nil {
		return clientCredentials{}, fmt.Errorf("generate Bearer secret: %w", err)
	}
	hmacSecret, err := generateCredential(random, "tph_")
	if err != nil {
		return clientCredentials{}, fmt.Errorf("generate HMAC secret: %w", err)
	}
	verifier := sha256.Sum256([]byte(bearerSecret))
	ciphertext, err := encryptHMACSecret(encryptionKey, hmacSecret, random)
	if err != nil {
		return clientCredentials{}, err
	}

	query := `
		INSERT INTO trusted_pool_integration_clients(
			client_id, external_pool_id, secret_hash, hmac_secret_encrypted,
			scopes, status, expires_at
		) VALUES ($1,$2,$3,$4,$5,'active',$6)
		ON CONFLICT (client_id) DO NOTHING
		RETURNING client_id`
	if options.Rotate {
		query = `
			UPDATE trusted_pool_integration_clients
			SET external_pool_id=$2,
			    secret_hash=$3,
			    hmac_secret_encrypted=$4,
			    scopes=$5,
			    status='active',
			    expires_at=CASE WHEN $6 THEN $7::timestamptz ELSE expires_at END,
			    updated_at=NOW()
			WHERE client_id=$1
			  AND (external_pool_id IS NULL OR external_pool_id=$2)
			RETURNING client_id`
	}

	var storedClientID string
	args := []any{options.ClientID, options.ExternalPoolID, hex.EncodeToString(verifier[:]), ciphertext, pq.Array(options.Scopes)}
	if options.Rotate {
		updateExpiry := options.ExpiresAt != nil || options.ClearExpiry
		args = append(args, updateExpiry, options.ExpiresAt)
	} else {
		args = append(args, options.ExpiresAt)
	}
	err = db.QueryRowContext(ctx, query, args...).Scan(&storedClientID)
	if errors.Is(err, sql.ErrNoRows) {
		if options.Rotate {
			return clientCredentials{}, errors.New("client does not exist or is already bound to another external pool")
		}
		return clientCredentials{}, errors.New("client already exists; use -rotate to replace its credentials")
	}
	if err != nil {
		return clientCredentials{}, fmt.Errorf("store trusted-pool integration client: %w", err)
	}
	if storedClientID != options.ClientID {
		return clientCredentials{}, errors.New("database returned an unexpected client ID")
	}
	return clientCredentials{BearerSecret: bearerSecret, HMACSecret: hmacSecret}, nil
}

func generateCredential(random io.Reader, prefix string) (string, error) {
	secretBytes := make([]byte, 32)
	if _, err := io.ReadFull(random, secretBytes); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(secretBytes), nil
}

func encryptHMACSecret(key []byte, plaintext string, random io.Reader) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create HMAC secret cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create HMAC secret GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(random, nonce); err != nil {
		return "", fmt.Errorf("generate HMAC secret nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func decodeEncryptionKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, errors.New("TOTP_ENCRYPTION_KEY must be a fixed 64-character hexadecimal value")
	}
	return key, nil
}

func parseScopes(value string) ([]string, error) {
	seen := make(map[string]struct{})
	for _, raw := range strings.Split(value, ",") {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}
		if _, ok := allowedTrustedPoolScopes[scope]; !ok {
			return nil, fmt.Errorf("unsupported trusted-pool scope %q", scope)
		}
		seen[scope] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for scope := range seen {
		result = append(result, scope)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil, errors.New("at least one trusted-pool scope is required")
	}
	return result, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
