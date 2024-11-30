;; Privacy-Preserving Identity Contract
;; This contract allows users to manage their digital identity while maintaining privacy
;; through encryption and selective disclosure mechanisms

;; Error codes
(define-constant ERROR-UNAUTHORIZED-ACCESS (err u100))
(define-constant ERROR-IDENTITY-EXISTS (err u101))
(define-constant ERROR-IDENTITY-NOT-FOUND (err u102))
(define-constant ERROR-INVALID-VERIFICATION-PROOF (err u103))
(define-constant ERROR-CREDENTIAL-EXPIRED (err u104))
(define-constant ERROR-INVALID-INPUT (err u105))

;; Constants for validation
(define-constant MIN-TIMESTAMP u1)
(define-constant MAX-TIMESTAMP u9999999999)

;; Data Maps
(define-map user-identities
    principal
    {
        identity-hash: (buff 32),
        registration-timestamp: uint,
        user-credentials: (list 10 (buff 32)),
        user-public-key: (buff 33),
        identity-revoked: bool
    }
)

(define-map credential-details
    (buff 32)  ;; credential hash
    {
        credential-issuer: principal,
        issuance-timestamp: uint,
        expiration-timestamp: uint,
        credential-category: (string-utf8 64),
        credential-revoked: bool
    }
)

(define-map disclosure-requests
    (buff 32)  ;; disclosure request ID
    {
        requesting-entity: principal,
        requested-attributes: (list 5 (string-utf8 64)),
        disclosure-approved: bool,
        verification-proof: (buff 32)
    }
)

;; Private functions
(define-private (validate-verification-proof 
    (submitted-proof (buff 32)) 
    (stored-hash (buff 32)))
    (is-eq submitted-proof stored-hash)
)

(define-private (check-credential-status 
    (credential-hash (buff 32))
    (credential-info {
        credential-issuer: principal, 
        issuance-timestamp: uint, 
        expiration-timestamp: uint, 
        credential-category: (string-utf8 64), 
        credential-revoked: bool
    }))
    (and
        (< block-height (get expiration-timestamp credential-info))
        (not (get credential-revoked credential-info))
    )
)

(define-private (validate-timestamp (timestamp uint))
    (and 
        (>= timestamp MIN-TIMESTAMP)
        (<= timestamp MAX-TIMESTAMP)
    )
)

(define-private (validate-buff32 (input (buff 32)))
    (is-eq (len input) u32)
)

(define-private (validate-buff33 (input (buff 33)))
    (is-eq (len input) u33)
)

;; Public functions
(define-public (register-user-identity 
    (user-public-key (buff 33)) 
    (user-identity-hash (buff 32)))
    (let
        ((current-user tx-sender))
        (asserts! (validate-buff33 user-public-key) ERROR-INVALID-INPUT)
        (asserts! (validate-buff32 user-identity-hash) ERROR-INVALID-INPUT)
        (asserts! (is-none (map-get? user-identities current-user)) ERROR-IDENTITY-EXISTS)
        (ok (map-set user-identities
            current-user
            {
                identity-hash: user-identity-hash,
                registration-timestamp: block-height,
                user-credentials: (list),
                user-public-key: user-public-key,
                identity-revoked: false
            }
        ))
    )
)

(define-public (add-user-credential 
    (credential-hash (buff 32))
    (expiration-timestamp uint)
    (credential-category (string-utf8 64)))
    (let
        ((current-user tx-sender)
         (user-identity (unwrap! (map-get? user-identities current-user) ERROR-IDENTITY-NOT-FOUND)))
        (asserts! (validate-buff32 credential-hash) ERROR-INVALID-INPUT)
        (asserts! (validate-timestamp expiration-timestamp) ERROR-INVALID-INPUT)
        (asserts! (> expiration-timestamp block-height) ERROR-CREDENTIAL-EXPIRED)
        (asserts! (not (get identity-revoked user-identity)) ERROR-UNAUTHORIZED-ACCESS)
        (map-set credential-details
            credential-hash
            {
                credential-issuer: current-user,
                issuance-timestamp: block-height,
                expiration-timestamp: expiration-timestamp,
                credential-category: credential-category,
                credential-revoked: false
            }
        )
        (ok (map-set user-identities
            current-user
            (merge user-identity
                {user-credentials: (unwrap! (as-max-len? (append (get user-credentials user-identity) credential-hash) u10)
                    ERROR-UNAUTHORIZED-ACCESS)}
            )
        ))
    )
)

(define-public (initiate-disclosure-request
    (request-identifier (buff 32))
    (required-attributes (list 5 (string-utf8 64))))
    (let
        ((requesting-user tx-sender))
        (asserts! (validate-buff32 request-identifier) ERROR-INVALID-INPUT)
        (asserts! (not (is-none (map-get? disclosure-requests request-identifier))) ERROR-INVALID-INPUT)
        (ok (map-set disclosure-requests
            request-identifier
            {
                requesting-entity: requesting-user,
                requested-attributes: required-attributes,
                disclosure-approved: false,
                verification-proof: 0x00
            }
        ))
    )
)

(define-public (approve-disclosure
    (request-identifier (buff 32))
    (verification-proof (buff 32)))
    (let
        ((current-user tx-sender)
         (disclosure-request (unwrap! (map-get? disclosure-requests request-identifier) ERROR-UNAUTHORIZED-ACCESS))
         (user-identity (unwrap! (map-get? user-identities current-user) ERROR-IDENTITY-NOT-FOUND)))
        (asserts! (validate-buff32 request-identifier) ERROR-INVALID-INPUT)
        (asserts! (validate-buff32 verification-proof) ERROR-INVALID-INPUT)
        (asserts! (not (get identity-revoked user-identity)) ERROR-UNAUTHORIZED-ACCESS)
        (asserts! (validate-verification-proof verification-proof (get identity-hash user-identity)) ERROR-INVALID-VERIFICATION-PROOF)
        (ok (map-set disclosure-requests
            request-identifier
            (merge disclosure-request
                {
                    disclosure-approved: true,
                    verification-proof: verification-proof
                }
            )
        ))
    )
)

(define-public (revoke-user-credential (credential-hash (buff 32)))
    (let
        ((current-user tx-sender)
         (credential-info (unwrap! (map-get? credential-details credential-hash) ERROR-UNAUTHORIZED-ACCESS)))
        (asserts! (validate-buff32 credential-hash) ERROR-INVALID-INPUT)
        (asserts! (is-eq (get credential-issuer credential-info) current-user) ERROR-UNAUTHORIZED-ACCESS)
        (ok (map-set credential-details
            credential-hash
            (merge credential-info {credential-revoked: true})
        ))
    )
)

(define-public (update-user-identity 
    (updated-identity-hash (buff 32)) 
    (updated-public-key (buff 33)))
    (let
        ((current-user tx-sender)
         (existing-identity (unwrap! (map-get? user-identities current-user) ERROR-IDENTITY-NOT-FOUND)))
        (asserts! (validate-buff32 updated-identity-hash) ERROR-INVALID-INPUT)
        (asserts! (validate-buff33 updated-public-key) ERROR-INVALID-INPUT)
        (asserts! (not (get identity-revoked existing-identity)) ERROR-UNAUTHORIZED-ACCESS)
        (ok (map-set user-identities
            current-user
            (merge existing-identity
                {
                    identity-hash: updated-identity-hash,
                    user-public-key: updated-public-key
                }
            )
        ))
    )
)

;; Read-only functions
(define-read-only (get-user-identity (user-principal principal))
    (map-get? user-identities user-principal)
)

(define-read-only (get-credential-details (credential-hash (buff 32)))
    (map-get? credential-details credential-hash)
)

(define-read-only (verify-disclosure-request
    (request-identifier (buff 32))
    (submitted-proof (buff 32)))
    (match (map-get? disclosure-requests request-identifier)
        disclosure-info (and
            (get disclosure-approved disclosure-info)
            (validate-verification-proof submitted-proof (get verification-proof disclosure-info))
        )
        false
    )
)

(define-read-only (check-credential-validity (credential-hash (buff 32)))
    (match (map-get? credential-details credential-hash)
        credential-info (check-credential-status credential-hash credential-info)
        false
    )
)