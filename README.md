# Go auth example

Run it (Go 1.22+):

```bash
go mod tidy
JWT_SECRET=$(openssl rand -hex 32) go run .
```

In another terminal, walk through it (needs `jq`):

```bash
# 1. Log in as Alice
RESP=$(curl -s -X POST localhost:8080/login \
  -d '{"email":"alice@example.com","password":"alice-pass"}')
ACCESS=$(echo "$RESP" | jq -r .access_token)
REFRESH=$(echo "$RESP" | jq -r .refresh_token)

# 2. Alice reads her own order -> 200
curl -s localhost:8080/orders/o1 -H "Authorization: Bearer $ACCESS"

# 3. Alice tries Bob's order -> 404 (authenticated, but not authorized)
curl -s localhost:8080/orders/o2 -H "Authorization: Bearer $ACCESS"

# 4. Alice tries the admin route -> 403
curl -s localhost:8080/admin/orders -H "Authorization: Bearer $ACCESS"

# 5. No token -> 401
curl -s localhost:8080/orders/o1

# 6. Refresh -> new access + new refresh token
NEW=$(curl -s -X POST localhost:8080/refresh -d "{\"refresh_token\":\"$REFRESH\"}")
NEW_REFRESH=$(echo "$NEW" | jq -r .refresh_token)

# 7. Reuse the OLD refresh token (simulates theft) -> 401, whole family revoked
curl -s -X POST localhost:8080/refresh -d "{\"refresh_token\":\"$REFRESH\"}"

# 8. Even the new one is now dead -> 401
curl -s -X POST localhost:8080/refresh -d "{\"refresh_token\":\"$NEW_REFRESH\"}"
```

Log in as `carol@example.com` / `carol-pass` to see the admin route return 200.
