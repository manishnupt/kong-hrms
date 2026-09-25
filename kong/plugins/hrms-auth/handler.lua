local jwt = require "resty.jwt"
local http = require "resty.http"
local bn = require "resty.openssl.bn"
local pkey = require "resty.openssl.pkey"
local cjson = require "cjson.safe"

local PLUGIN_NAME = "hrms-auth"

local HrmsAuth = {
    PRIORITY = 1000,
    VERSION = "1.5.0",
}

-- ============================================================
-- CONFIGURATION
-- ============================================================

local KEYCLOAK_BASE_URL = "https://accounts.pp.worksphere.works"

local CLIENT_ID = "hrms-client"

-- JWKS cache: 5 minutes
local JWKS_CACHE_TTL = 300

-- ============================================================
-- ERROR HELPER
-- ============================================================

local function unauthorized(code, message, internal_reason)

    local elapsed_ms = "unknown"

    if kong.ctx.shared.hrms_auth_start_time then
        elapsed_ms =
            math.floor(
                (ngx.now() - kong.ctx.shared.hrms_auth_start_time) * 1000
            )
    end

    if internal_reason then
        kong.log.warn(
            "HRMS AUTH - ",
            code,
            ": ",
            internal_reason,
            " elapsed_ms=",
            elapsed_ms
        )
    else
        kong.log.warn(
            "HRMS AUTH - ",
            code,
            " elapsed_ms=",
            elapsed_ms
        )
    end

    return kong.response.exit(
        401,
        {
            code = code,
            message = message
        }
    )
end

-- ============================================================
-- BASE64URL DECODE
-- ============================================================

local function base64url_decode(value)

    if not value or value == "" then
        return nil, "empty value"
    end

    value = value:gsub("-", "+")
    value = value:gsub("_", "/")

    local remainder = #value % 4

    if remainder == 1 then
        return nil, "invalid base64url length"
    elseif remainder == 2 then
        value = value .. "=="
    elseif remainder == 3 then
        value = value .. "="
    end

    local decoded = ngx.decode_base64(value)

    if not decoded then
        return nil, "invalid base64url value"
    end

    return decoded
end

-- ============================================================
-- TENANT VALIDATION
-- ============================================================

local function validate_tenant(tenant)

    if not tenant or tenant == "" then
        return false
    end

    -- Prevent arbitrary values from being inserted into
    -- the Keycloak URL.
    if not tenant:match("^[A-Za-z0-9._%-]+$") then
        return false
    end

    return true
end

-- ============================================================
-- FETCH JWKS FROM KEYCLOAK
-- ============================================================

local function fetch_jwks(tenant)

    local httpc = http.new()

    httpc:set_timeouts(2000, 2000, 3000) -- connect, send, read (ms)

    local url =
        KEYCLOAK_BASE_URL ..
        "/realms/" ..
        tenant ..
        "/protocol/openid-connect/certs"

    kong.log.debug(
        "HRMS AUTH - Fetching JWKS. tenant=",
        tenant,
        " url=",
        url
    )

    local request_start = ngx.now()

    local response, err =
        httpc:request_uri(
            url,
            {
                method = "GET",

                ssl_verify = true,

                headers = {
                    ["Accept"] = "application/json"
                }
            }
        )

    local request_duration_ms =
        math.floor((ngx.now() - request_start) * 1000)

    if not response then

        kong.log.err(
            "HRMS AUTH - JWKS request failed. tenant=",
            tenant,
            " error=",
            tostring(err),
            " duration_ms=",
            request_duration_ms
        )

        return nil, "JWKS request failed"
    end

    kong.log.debug(
        "HRMS AUTH - JWKS HTTP response received. tenant=",
        tenant,
        " status=",
        response.status,
        " duration_ms=",
        request_duration_ms
    )

    if response.status ~= 200 then

        kong.log.err(
            "HRMS AUTH - JWKS returned HTTP ",
            tostring(response.status),
            ". tenant=",
            tenant
        )

        return nil,
            "JWKS endpoint returned HTTP " ..
            tostring(response.status)
    end

    local response_body =
        tostring(response.body)

    local data, decode_err =
        cjson.decode(response_body)

    if not data then

        kong.log.err(
            "HRMS AUTH - Invalid JWKS JSON. tenant=",
            tenant,
            " error=",
            tostring(decode_err)
        )

        return nil, "Invalid JWKS JSON"
    end

    if type(data.keys) ~= "table" then

        kong.log.err(
            "HRMS AUTH - JWKS contains no keys. tenant=",
            tenant
        )

        return nil,
            "JWKS response does not contain keys"
    end

    kong.log.debug(
        "HRMS AUTH - JWKS loaded. tenant=",
        tenant,
        " key_count=",
        tostring(#data.keys)
    )

    return data
end

-- ============================================================
-- GET JWKS FROM CACHE
-- ============================================================

local function get_jwks(tenant)

    local cache_key =
        "hrms-auth:jwks:" .. tenant

    local lookup_start = ngx.now()

    local jwks, err =
        kong.cache:get(
            cache_key,
            nil,

            function()
                -- This callback only runs on a cache miss,
                -- so seeing this log line means we're about
                -- to make a blocking call out to Keycloak.
                kong.log.debug(
                    "HRMS AUTH - JWKS cache miss. tenant=",
                    tenant
                )

                return fetch_jwks(tenant)
            end,

            JWKS_CACHE_TTL
        )

    local lookup_duration_ms =
        math.floor((ngx.now() - lookup_start) * 1000)

    if not jwks then

        kong.log.err(
            "HRMS AUTH - Unable to get JWKS. tenant=",
            tenant,
            " error=",
            tostring(err),
            " duration_ms=",
            lookup_duration_ms
        )

        return nil, "Unable to retrieve JWKS"
    end

    kong.log.debug(
        "HRMS AUTH - JWKS lookup complete. tenant=",
        tenant,
        " duration_ms=",
        lookup_duration_ms
    )

    return jwks
end

-- ============================================================
-- FORCE JWKS REFRESH
--
-- Used when kid is not found in cached JWKS.
-- This handles Keycloak signing-key rotation.
-- ============================================================

local function refresh_jwks(tenant)

    kong.log.info(
        "HRMS AUTH - Refreshing JWKS. tenant=",
        tenant
    )

    local cache_key =
        "hrms-auth:jwks:" .. tenant

    -- Drop the stale cache entry, then re-fetch through
    -- kong.cache so concurrent requests share a single
    -- lock/fetch instead of each firing its own request
    -- at Keycloak, and so the refreshed JWKS is actually
    -- cached for subsequent requests.
    kong.cache:invalidate_local(cache_key)

    local refresh_start = ngx.now()

    local jwks, err =
        kong.cache:get(
            cache_key,
            nil,

            function()
                return fetch_jwks(tenant)
            end,

            JWKS_CACHE_TTL
        )

    local refresh_duration_ms =
        math.floor((ngx.now() - refresh_start) * 1000)

    if not jwks then

        kong.log.err(
            "HRMS AUTH - JWKS refresh failed. tenant=",
            tenant,
            " error=",
            tostring(err),
            " duration_ms=",
            refresh_duration_ms
        )

        return nil, "Unable to refresh JWKS"
    end

    kong.log.info(
        "HRMS AUTH - JWKS refresh complete. tenant=",
        tenant,
        " duration_ms=",
        refresh_duration_ms
    )

    return jwks
end

-- ============================================================
-- FIND SIGNING KEY
-- ============================================================

local function find_signing_key(jwks, kid)

    if not jwks or
       type(jwks.keys) ~= "table" then

        return nil, "Invalid JWKS"
    end

    for _, key in ipairs(jwks.keys) do

        if key.kid == kid then

            -- Keycloak should give us RSA keys.
            if key.kty ~= "RSA" then

                return nil,
                    "Signing key is not RSA"
            end

            -- Only RS256 is supported.
            if key.alg and
               key.alg ~= "RS256" then

                return nil,
                    "Signing key algorithm is not RS256"
            end

            -- Must be a signing key.
            if key.use and
               key.use ~= "sig" then

                return nil,
                    "Signing key is not for signatures"
            end

            if not key.n then

                return nil,
                    "RSA key missing modulus"
            end

            if not key.e then

                return nil,
                    "RSA key missing exponent"
            end

            return key
        end
    end

    return nil,
        "Signing key not found"
end

-- ============================================================
-- CREATE RSA PUBLIC KEY FROM JWK
-- ============================================================

local function create_rsa_public_key(jwk)

    local n_binary, n_err =
        base64url_decode(jwk.n)

    if not n_binary then

        return nil,
            "Failed to decode RSA modulus: " ..
            tostring(n_err)
    end

    local e_binary, e_err =
        base64url_decode(jwk.e)

    if not e_binary then

        return nil,
            "Failed to decode RSA exponent: " ..
            tostring(e_err)
    end

    local n_bn, n_bn_err =
        bn.new(
            n_binary,
            2
        )

    if not n_bn then

        return nil,
            "Failed to create modulus BIGNUM: " ..
            tostring(n_bn_err)
    end

    local e_bn, e_bn_err =
        bn.new(
            e_binary,
            2
        )

    if not e_bn then

        return nil,
            "Failed to create exponent BIGNUM: " ..
            tostring(e_bn_err)
    end

    local public_key, key_err =
        pkey.new(
            {
                type = "RSA",

                params = {
                    n = n_bn,
                    e = e_bn
                }
            }
        )

    if not public_key then

        return nil,
            "Failed to create RSA public key: " ..
            tostring(key_err)
    end

    return public_key
end

-- ============================================================
-- VALIDATE JWT CLAIMS
-- ============================================================

local function validate_claims(
    claims,
    tenant
)

    if not claims then

        return false,
            "JWT payload is missing"
    end

    -- ========================================================
    -- ISSUER
    -- ========================================================

    local expected_issuer =
        KEYCLOAK_BASE_URL ..
        "/realms/" ..
        tenant

    if claims.iss ~= expected_issuer then

        return false,
            "Token issuer does not match tenant"
    end

    -- ========================================================
    -- EXPIRATION
    -- ========================================================

    if not claims.exp then

        return false,
            "Token missing exp claim"
    end

    if type(claims.exp) ~= "number" then

        return false,
            "Token exp is not numeric"
    end

    if claims.exp <= ngx.time() then

        return false,
            "Token has expired"
    end

    -- ========================================================
    -- AUTHORIZED PARTY
    -- ========================================================

    if claims.azp ~= CLIENT_ID then

        return false,
            "Token azp does not match client"
    end

    -- ========================================================
    -- AUDIENCE
    --
    -- Keycloak can return:
    --
    -- "aud": "hrms-client"
    --
    -- OR:
    --
    -- "aud": ["hrms-client", "account"]
    -- ========================================================


    return true
end

-- ============================================================
-- MAIN ACCESS HANDLER
-- ============================================================

function HrmsAuth:access(conf)

    kong.ctx.shared.hrms_auth_start_time = ngx.now()

    kong.log.debug(
        "HRMS AUTH - Access phase started. method=",
        kong.request.get_method(),
        " path=",
        kong.request.get_path()
    )

     -- Allow CORS preflight requests
    if kong.request.get_method() == "OPTIONS" then
        return
    end

    -- ========================================================
    -- 1. TENANT HEADER
    -- ========================================================

    local tenant =
        kong.request.get_header(
            conf.tenant_header
        )

    if not tenant or tenant == "" then

        return unauthorized(
            "AUTH_TENANT_MISSING",
            "Tenant ID is required"
        )
    end

    -- ========================================================
    -- 2. TENANT FORMAT
    -- ========================================================

    if not validate_tenant(tenant) then

        return unauthorized(
            "AUTH_TENANT_INVALID",
            "Invalid tenant ID"
        )
    end

    -- ========================================================
    -- 3. AUTHORIZATION HEADER
    -- ========================================================

    local authorization =
        kong.request.get_header(
            conf.auth_header
        )

    if not authorization or
       authorization == "" then

        return unauthorized(
            "AUTH_TOKEN_MISSING",
            "Authentication token is required"
        )
    end

    -- ========================================================
    -- 4. BEARER TOKEN
    -- ========================================================

    local token =
        authorization:match(
            "^Bearer%s+(.+)$"
        )

    if not token then

        return unauthorized(
            "AUTH_TOKEN_INVALID",
            "Invalid authentication token"
        )
    end

    -- ========================================================
    -- 5. PARSE JWT
    -- ========================================================

    local jwt_obj =
        jwt:load_jwt(token)

    if not jwt_obj or
       not jwt_obj.valid then

        return unauthorized(
            "AUTH_TOKEN_INVALID",
            "Invalid authentication token",
            "JWT parsing failed"
        )
    end

    local header =
        jwt_obj.header

    if not header then

        return unauthorized(
            "AUTH_TOKEN_INVALID",
            "Invalid authentication token",
            "JWT header missing"
        )
    end

    -- ========================================================
    -- 6. JWT ALGORITHM
    -- ========================================================

    if header.alg ~= "RS256" then

        return unauthorized(
            "AUTH_TOKEN_ALGORITHM_INVALID",
            "Unsupported authentication token",
            "Unsupported JWT algorithm: " ..
                tostring(header.alg)
        )
    end

    -- ========================================================
    -- 7. JWT KEY ID
    -- ========================================================

    local kid =
        header.kid

    if not kid or kid == "" then

        return unauthorized(
            "AUTH_TOKEN_INVALID",
            "Invalid authentication token",
            "JWT kid is missing"
        )
    end

    kong.log.debug(
        "HRMS AUTH - JWT parsed. tenant=",
        tenant,
        " kid=",
        kid
    )

    -- ========================================================
    -- 8. GET JWKS FROM CACHE
    -- ========================================================

    local jwks, jwks_err =
        get_jwks(tenant)

    if not jwks then

        return unauthorized(
            "AUTH_JWKS_UNAVAILABLE",
            "Authentication service temporarily unavailable",
            jwks_err
        )
    end

    -- ========================================================
    -- 9. FIND SIGNING KEY
    -- ========================================================

    local jwk, key_err =
        find_signing_key(
            jwks,
            kid
        )

    -- ========================================================
    -- 10. KEY NOT FOUND
    --
    -- Try a fresh JWKS request.
    --
    -- This handles Keycloak signing-key rotation.
    -- ========================================================

    if not jwk then

        kong.log.info(
            "HRMS AUTH - kid not found in cached JWKS. ",
            "Refreshing JWKS. tenant=",
            tenant
        )

        jwks, jwks_err =
            refresh_jwks(tenant)

        if not jwks then

            return unauthorized(
                "AUTH_JWKS_UNAVAILABLE",
                "Authentication service temporarily unavailable",
                jwks_err
            )
        end

        jwk, key_err =
            find_signing_key(
                jwks,
                kid
            )

        if not jwk then

            return unauthorized(
                "AUTH_TOKEN_KEY_INVALID",
                "Invalid authentication token",
                "Signing key not found after JWKS refresh"
            )
        end
    end

    -- ========================================================
    -- 11. CREATE RSA PUBLIC KEY
    -- ========================================================

    local public_key,
          public_key_err =
        create_rsa_public_key(
            jwk
        )

    if not public_key then

        return unauthorized(
            "AUTH_TOKEN_KEY_INVALID",
            "Invalid authentication token",
            public_key_err
        )
    end

    -- ========================================================
    -- 12. RSA PUBLIC KEY → PEM
    -- ========================================================

    local public_key_pem,
          pem_err =
        public_key:to_PEM(
            "public"
        )

    if not public_key_pem then

        return unauthorized(
            "AUTH_TOKEN_KEY_INVALID",
            "Invalid authentication token",
            "Failed to create public key PEM: " ..
                tostring(pem_err)
        )
    end

    -- ========================================================
    -- 13. VERIFY JWT SIGNATURE
    -- ========================================================

    local verifier =
        jwt.new(
            {
                alg_whitelist = {
                    RS256 = true
                }
            }
        )

    local verified =
        verifier:verify(
            public_key_pem,
            token
        )

    if not verified or
       not verified.verified then

        local verify_reason = "unknown"

        if verified then

            verify_reason =
                tostring(
                    verified.reason
                )
        end

        return unauthorized(
            "AUTH_TOKEN_SIGNATURE_INVALID",
            "Invalid authentication token",
            "JWT signature verification failed: " ..
                verify_reason
        )
    end

    -- ========================================================
    -- 14. GET JWT CLAIMS
    -- ========================================================

    local claims =
        verified.payload

    -- ========================================================
    -- 15. VALIDATE CLAIMS
    -- ========================================================

    local claims_valid,
          claims_err =
        validate_claims(
            claims,
            tenant
        )

    if not claims_valid then

        if claims_err ==
           "Token has expired" then

            return unauthorized(
                "AUTH_TOKEN_EXPIRED",
                "Authentication token has expired",
                claims_err
            )
        end

        if claims_err ==
           "Token issuer does not match tenant" then

            return unauthorized(
                "AUTH_TOKEN_ISSUER_INVALID",
                "Authentication token does not belong to this tenant",
                claims_err
            )
        end

        if claims_err ==
           "Token azp does not match client" then

            return unauthorized(
                "AUTH_TOKEN_CLIENT_INVALID",
                "Authentication token is not valid for this application",
                claims_err
            )
        end

        if claims_err ==
           "Token audience does not contain client" then

            return unauthorized(
                "AUTH_TOKEN_AUDIENCE_INVALID",
                "Authentication token audience is invalid",
                claims_err
            )
        end

        return unauthorized(
            "AUTH_TOKEN_INVALID",
            "Invalid authentication token",
            claims_err
        )
    end

    -- ========================================================
    -- 16. SUCCESS
    -- ========================================================

    kong.log.info(
        "HRMS AUTH - Authentication successful. tenant=",
        tenant,
        " elapsed_ms=",
        math.floor(
            (ngx.now() - kong.ctx.shared.hrms_auth_start_time) * 1000
        )
    )

    -- No response means continue to upstream.
end

return HrmsAuth