# frozen_string_literal: true

require "base64"
require "openssl"
require "json"

module DidResolver
  module Methods
    # DID Key Method Resolver
    #
    # Resolves did:key DIDs according to the DID Key Method Specification
    # @see https://w3c-ccg.github.io/did-method-key/
    #
    # did:key is a self-describing DID that encodes the public key directly
    # in the DID identifier using multibase + multicodec encoding.
    #
    # Supported key types:
    #   - Ed25519 (multicodec: 0xed)
    #   - X25519 (multicodec: 0xec)
    #   - secp256k1 (multicodec: 0xe7)
    #   - P-256 (multicodec: 0x1200)
    #   - P-384 (multicodec: 0x1201)
    #   - P-521 (multicodec: 0x1202)
    #   - RSA (multicodec: 0x1205)
    #   - jwk_jcs-pub (multicodec: 0xeb51) - EBSI/JCS encoded JWK
    #
    # @example
    #   resolver = DidResolver::Resolver.new(DidResolver::Methods::Key.resolver)
    #   result = resolver.resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
    #
    class Key
      # Multicodec prefixes for key types
      # @see https://github.com/multiformats/multicodec/blob/master/table.csv
      MULTICODEC = {
        ed25519_pub: 0xed,
        x25519_pub: 0xec,
        secp256k1_pub: 0xe7,
        p256_pub: 0x1200,
        p384_pub: 0x1201,
        p521_pub: 0x1202,
        rsa_pub: 0x1205,
        jwk_jcs_pub: 0xeb51  # EBSI jwk_jcs-pub codec
      }.freeze

      # Reverse lookup
      MULTICODEC_TO_TYPE = MULTICODEC.invert.freeze

      # Key type to verification method type mapping
      KEY_TYPE_TO_VM_TYPE = {
        ed25519_pub: "Ed25519VerificationKey2020",
        x25519_pub: "X25519KeyAgreementKey2020",
        secp256k1_pub: "EcdsaSecp256k1VerificationKey2019",
        p256_pub: "JsonWebKey2020",
        p384_pub: "JsonWebKey2020",
        p521_pub: "JsonWebKey2020",
        rsa_pub: "JsonWebKey2020",
        jwk_jcs_pub: "JsonWebKey2020"
      }.freeze

      # Key type to JWK curve mapping
      KEY_TYPE_TO_CURVE = {
        ed25519_pub: "Ed25519",
        x25519_pub: "X25519",
        secp256k1_pub: "secp256k1",
        p256_pub: "P-256",
        p384_pub: "P-384",
        p521_pub: "P-521"
        # jwk_jcs_pub curve comes from the embedded JWK
      }.freeze

      class << self
        # Get the resolver hash for registration
        # @return [Hash] { "key" => resolve_proc }
        def resolver
          { "key" => method(:resolve) }
        end

        # Resolve a did:key DID
        # @param did [String] The full DID string
        # @param parsed [ParsedDID] Parsed DID components
        # @param _resolver [Resolver] Parent resolver
        # @param _options [Hash] Resolution options
        # @return [ResolutionResult]
        def resolve(did, parsed, _resolver, _options = {})
          # Extract the method-specific identifier (without fragment)
          method_specific_id = parsed.id

          # Parse the multibase-encoded key
          key_data = decode_multibase_key(method_specific_id)
          return key_data if key_data.is_a?(ResolutionResult) # Error case

          key_type = key_data[:type]
          public_key_bytes = key_data[:bytes]

          # Build the DID Document based on key type
          did_document = if key_type == :jwk_jcs_pub
            build_did_document_from_jwk_jcs(did, method_specific_id, public_key_bytes)
          else
            build_did_document(did, key_type, public_key_bytes)
          end

          return did_document if did_document.is_a?(ResolutionResult) # Error case

          ResolutionResult.success(did_document)
        rescue StandardError => e
          ResolutionResult.error("invalidDid", "Failed to resolve did:key: #{e.message}")
        end

        private

        # Decode a multibase-encoded public key
        # @param multibase_key [String] The multibase-encoded key (e.g., z6Mk...)
        # @return [Hash] { type: Symbol, bytes: String }
        def decode_multibase_key(multibase_key)
          # Check multibase prefix (z = base58btc)
          unless multibase_key.start_with?("z")
            return ResolutionResult.invalid_did(
              "did:key:#{multibase_key}",
              "Unsupported multibase encoding. Expected 'z' (base58btc)"
            )
          end

          # Decode base58btc (without the 'z' prefix)
          encoded = multibase_key[1..]
          decoded = decode_base58(encoded)

          # Extract multicodec prefix
          multicodec, key_bytes = extract_multicodec(decoded)

          key_type = MULTICODEC_TO_TYPE[multicodec]
          unless key_type
            return ResolutionResult.invalid_did(
              "did:key:#{multibase_key}",
              "Unsupported key type multicodec: 0x#{multicodec.to_s(16)}"
            )
          end

          { type: key_type, bytes: key_bytes }
        end

        # Extract multicodec prefix from bytes
        # Multicodec uses unsigned varint encoding (LEB128)
        # @see https://github.com/multiformats/unsigned-varint
        def extract_multicodec(bytes)
          decode_uvarint(bytes)
        end

        # Decode an unsigned varint (LEB128) from the beginning of bytes
        # @param bytes [String] Binary string
        # @return [Array<Integer, String>] [value, remaining_bytes]
        def decode_uvarint(bytes)
          result = 0
          shift = 0
          offset = 0

          loop do
            raise "Varint too long" if offset >= 9 # Max 9 bytes for 64-bit
            raise "Unexpected end of bytes" if offset >= bytes.bytesize

            byte = bytes[offset].ord
            offset += 1

            # Add the lower 7 bits to result
            result |= (byte & 0x7f) << shift
            shift += 7

            # If MSB is 0, we're done
            break if (byte & 0x80).zero?
          end

          [result, bytes[offset..]]
        end

        # Build DID Document for the key
        def build_did_document(did, key_type, public_key_bytes)
          vm_type = KEY_TYPE_TO_VM_TYPE[key_type]
          vm_id = "#{did}##{did.split(':').last}"

          # Build verification method
          verification_method = {
            "id" => vm_id,
            "type" => vm_type,
            "controller" => did
          }

          # Add public key in appropriate format
          case key_type
          when :ed25519_pub, :x25519_pub
            # Use multibase encoding for Ed25519/X25519
            verification_method["publicKeyMultibase"] = "z" + encode_base58(
              [MULTICODEC[key_type]].pack("C") + public_key_bytes
            )
          else
            # Use JWK for other key types
            verification_method["publicKeyJwk"] = build_jwk(key_type, public_key_bytes)
          end

          # Build verification relationships based on key type
          authentication = []
          assertion_method = []
          key_agreement = []
          capability_invocation = []
          capability_delegation = []

          case key_type
          when :ed25519_pub
            authentication << vm_id
            assertion_method << vm_id
            capability_invocation << vm_id
            capability_delegation << vm_id
          when :x25519_pub
            key_agreement << vm_id
          when :secp256k1_pub, :p256_pub, :p384_pub, :p521_pub
            authentication << vm_id
            assertion_method << vm_id
            capability_invocation << vm_id
            capability_delegation << vm_id
          end

          DIDDocument.new(
            id: did,
            context: [
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/suites/ed25519-2020/v1",
              "https://w3id.org/security/suites/x25519-2020/v1"
            ],
            verification_method: [verification_method],
            authentication: authentication.any? ? authentication : nil,
            assertion_method: assertion_method.any? ? assertion_method : nil,
            key_agreement: key_agreement.any? ? key_agreement : nil,
            capability_invocation: capability_invocation.any? ? capability_invocation : nil,
            capability_delegation: capability_delegation.any? ? capability_delegation : nil
          )
        end

        # Build DID Document from jwk_jcs-pub encoded JWK
        # This is the EBSI format where the key bytes are a JSON-encoded JWK
        # @see https://github.com/multiformats/multicodec/pull/307
        def build_did_document_from_jwk_jcs(did, method_specific_id, public_key_bytes)
          # The bytes are UTF-8 encoded JSON of the JWK
          jwk_json = public_key_bytes.force_encoding("UTF-8")

          begin
            public_key_jwk = JSON.parse(jwk_json)
          rescue JSON::ParserError => e
            return ResolutionResult.error("invalidDid", "Invalid JWK JSON in did:key: #{e.message}")
          end

          # Validate JWK has required fields
          unless public_key_jwk["kty"]
            return ResolutionResult.error("invalidDid", "JWK missing required 'kty' parameter")
          end

          # Verify the JWK is in canonical form (JCS - lexicographically sorted)
          canonical_jwk = canonicalize_jwk(public_key_jwk)
          if JSON.generate(public_key_jwk) != JSON.generate(canonical_jwk)
            return ResolutionResult.error("invalidDid", "The JWK embedded in the DID is not correctly formatted (must be JCS canonical)")
          end

          # Build key ID using the method-specific identifier
          key_id = "#{did}##{method_specific_id}"

          verification_method = {
            "id" => key_id,
            "type" => "JsonWebKey2020",
            "controller" => did,
            "publicKeyJwk" => public_key_jwk
          }

          # Build verification relationships
          # All signing-capable keys get all relationships
          DIDDocument.new(
            id: did,
            context: [
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/suites/jws-2020/v1"
            ],
            verification_method: [verification_method],
            authentication: [key_id],
            assertion_method: [key_id],
            capability_invocation: [key_id],
            capability_delegation: [key_id]
          )
        end

        # Canonicalize JWK according to JCS (only required members, lexicographically sorted)
        # @see https://www.rfc-editor.org/rfc/rfc7638 (JWK Thumbprint)
        def canonicalize_jwk(jwk)
          case jwk["kty"]
          when "EC"
            { "crv" => jwk["crv"], "kty" => jwk["kty"], "x" => jwk["x"], "y" => jwk["y"] }
          when "OKP"
            { "crv" => jwk["crv"], "kty" => jwk["kty"], "x" => jwk["x"] }
          when "RSA"
            { "e" => jwk["e"], "kty" => jwk["kty"], "n" => jwk["n"] }
          else
            jwk
          end
        end

        # Build JWK from public key bytes
        def build_jwk(key_type, public_key_bytes)
          curve = KEY_TYPE_TO_CURVE[key_type]

          case key_type
          when :secp256k1_pub, :p256_pub, :p384_pub, :p521_pub
            # EC key - uncompressed point format (04 || x || y)
            if public_key_bytes[0] == "\x04"
              # Uncompressed
              coord_length = (public_key_bytes.bytesize - 1) / 2
              x = public_key_bytes[1, coord_length]
              y = public_key_bytes[1 + coord_length, coord_length]
            else
              # Compressed - would need to decompress
              # For now, just use the raw bytes
              x = public_key_bytes
              y = nil
            end

            jwk = {
              "kty" => "EC",
              "crv" => curve,
              "x" => base64url_encode(x)
            }
            jwk["y"] = base64url_encode(y) if y
            jwk
          when :rsa_pub
            # RSA public key (DER encoded)
            {
              "kty" => "RSA",
              "n" => base64url_encode(public_key_bytes),
              "e" => base64url_encode("\x01\x00\x01") # Common exponent 65537
            }
          else
            # OKP keys (Ed25519, X25519)
            {
              "kty" => "OKP",
              "crv" => curve,
              "x" => base64url_encode(public_key_bytes)
            }
          end
        end

        # Base58 Bitcoin alphabet
        BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        def decode_base58(str)
          int_val = 0
          str.each_char do |c|
            int_val = int_val * 58 + BASE58_ALPHABET.index(c)
          end

          # Convert to bytes
          hex = int_val.to_s(16)
          hex = "0" + hex if hex.length.odd?

          # Handle leading zeros
          leading_zeros = str.chars.take_while { |c| c == "1" }.count
          ("\x00" * leading_zeros) + [hex].pack("H*")
        end

        def encode_base58(bytes)
          # Count leading zeros
          leading_zeros = bytes.bytes.take_while(&:zero?).count

          # Convert to integer
          int_val = bytes.unpack1("H*").to_i(16)

          # Convert to base58
          result = ""
          while int_val > 0
            int_val, remainder = int_val.divmod(58)
            result = BASE58_ALPHABET[remainder] + result
          end

          # Add leading 1s for each leading zero byte
          ("1" * leading_zeros) + result
        end

        def base64url_encode(bytes)
          Base64.urlsafe_encode64(bytes, padding: false)
        end
      end
    end
  end
end
