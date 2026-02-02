# frozen_string_literal: true

require "base64"
require "json"

module DidResolver
  module Methods
    # DID JWK Method Resolver
    #
    # Resolves did:jwk DIDs according to the DID JWK Method Specification
    # @see https://github.com/quartzjer/did-jwk/blob/main/spec.md
    #
    # did:jwk encodes a JWK directly in the DID identifier using base64url encoding.
    # The DID Document is deterministically generated from the JWK.
    #
    # @example
    #   resolver = DidResolver::Resolver.new(DidResolver::Methods::Jwk.resolver)
    #   result = resolver.resolve("did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ii4uLiIsInkiOiIuLi4ifQ")
    #
    class Jwk
      # JWK key type to verification method type mapping
      KEY_TYPE_TO_VM_TYPE = {
        "EC" => "JsonWebKey2020",
        "OKP" => "JsonWebKey2020",
        "RSA" => "JsonWebKey2020"
      }.freeze

      # Curves that support key agreement (ECDH)
      KEY_AGREEMENT_CURVES = %w[X25519 X448 P-256 P-384 P-521].freeze

      # Curves that support signing
      SIGNING_CURVES = %w[Ed25519 Ed448 P-256 P-384 P-521 secp256k1].freeze

      class << self
        # Get the resolver hash for registration
        # @return [Hash] { "jwk" => resolve_proc }
        def resolver
          { "jwk" => method(:resolve) }
        end

        # Resolve a did:jwk DID
        # @param did [String] The full DID string
        # @param parsed [ParsedDID] Parsed DID components
        # @param _resolver [Resolver] Parent resolver
        # @param _options [Hash] Resolution options
        # @return [ResolutionResult]
        def resolve(did, parsed, _resolver, _options = {})
          # Decode the JWK from the method-specific identifier
          jwk = decode_jwk(parsed.id)
          return jwk if jwk.is_a?(ResolutionResult) # Error case

          # Validate the JWK
          validation = validate_jwk(jwk)
          return validation if validation

          # Build the DID Document
          did_document = build_did_document(did, jwk)

          ResolutionResult.success(did_document)
        rescue StandardError => e
          ResolutionResult.error("invalidDid", "Failed to resolve did:jwk: #{e.message}")
        end

        private

        # Decode the base64url-encoded JWK
        # @param encoded [String] Base64url encoded JWK
        # @return [Hash, ResolutionResult]
        def decode_jwk(encoded)
          # Add padding if needed
          padding = (4 - encoded.length % 4) % 4
          padded = encoded + ("=" * padding)

          decoded = Base64.urlsafe_decode64(padded)
          JSON.parse(decoded)
        rescue ArgumentError => e
          ResolutionResult.invalid_did("did:jwk:#{encoded}", "Invalid base64url encoding: #{e.message}")
        rescue JSON::ParserError => e
          ResolutionResult.invalid_did("did:jwk:#{encoded}", "Invalid JSON in JWK: #{e.message}")
        end

        # Validate the JWK structure
        # @param jwk [Hash] The JWK
        # @return [ResolutionResult, nil] Error result or nil if valid
        def validate_jwk(jwk)
          unless jwk["kty"]
            return ResolutionResult.error("invalidDid", "JWK missing required 'kty' parameter")
          end

          unless %w[EC OKP RSA].include?(jwk["kty"])
            return ResolutionResult.error(
              "invalidDid",
              "Unsupported JWK key type: #{jwk["kty"]}"
            )
          end

          # EC keys require curve and coordinates
          if jwk["kty"] == "EC"
            unless jwk["crv"] && jwk["x"]
              return ResolutionResult.error("invalidDid", "EC JWK missing required 'crv' or 'x' parameter")
            end
          end

          # OKP keys require curve and x
          if jwk["kty"] == "OKP"
            unless jwk["crv"] && jwk["x"]
              return ResolutionResult.error("invalidDid", "OKP JWK missing required 'crv' or 'x' parameter")
            end
          end

          # RSA keys require n and e
          if jwk["kty"] == "RSA"
            unless jwk["n"] && jwk["e"]
              return ResolutionResult.error("invalidDid", "RSA JWK missing required 'n' or 'e' parameter")
            end
          end

          nil
        end

        # Build DID Document for the JWK
        def build_did_document(did, jwk)
          # Create a public-only JWK (strip private key parameters)
          public_jwk = jwk.reject { |k, _| %w[d p q dp dq qi].include?(k) }

          vm_id = "#{did}#0"

          # Build verification method
          verification_method = {
            "id" => vm_id,
            "type" => KEY_TYPE_TO_VM_TYPE[jwk["kty"]],
            "controller" => did,
            "publicKeyJwk" => public_jwk
          }

          # Determine verification relationships based on key type and curve
          authentication = []
          assertion_method = []
          key_agreement = []
          capability_invocation = []
          capability_delegation = []

          curve = jwk["crv"]

          # Key agreement capability
          if KEY_AGREEMENT_CURVES.include?(curve)
            key_agreement << vm_id
          end

          # Signing capability
          if SIGNING_CURVES.include?(curve) || jwk["kty"] == "RSA"
            authentication << vm_id
            assertion_method << vm_id
            capability_invocation << vm_id
            capability_delegation << vm_id
          end

          DIDDocument.new(
            id: did,
            context: [
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/suites/jws-2020/v1"
            ],
            verification_method: [verification_method],
            authentication: authentication.any? ? authentication : nil,
            assertion_method: assertion_method.any? ? assertion_method : nil,
            key_agreement: key_agreement.any? ? key_agreement : nil,
            capability_invocation: capability_invocation.any? ? capability_invocation : nil,
            capability_delegation: capability_delegation.any? ? capability_delegation : nil
          )
        end
      end
    end
  end
end
