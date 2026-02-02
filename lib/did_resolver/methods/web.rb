# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

module DidResolver
  module Methods
    # DID Web Method Resolver
    #
    # Resolves did:web DIDs according to the DID Web Method Specification
    # @see https://w3c-ccg.github.io/did-method-web/
    #
    # DID Web syntax:
    #   did:web:<domain>                     -> https://<domain>/.well-known/did.json
    #   did:web:<domain>:<path>              -> https://<domain>/<path>/did.json
    #   did:web:<domain>%3A<port>            -> https://<domain>:<port>/.well-known/did.json
    #
    # @example
    #   resolver = DidResolver::Resolver.new(DidResolver::Methods::Web.resolver)
    #   result = resolver.resolve("did:web:example.com")
    #
    class Web
      DEFAULT_TIMEOUT = 10

      class << self
        # Get the resolver hash for registration
        # @return [Hash] { "web" => resolve_proc }
        def resolver
          { "web" => method(:resolve) }
        end

        # Resolve a did:web DID
        # @param did [String] The full DID string
        # @param parsed [ParsedDID] Parsed DID components
        # @param _resolver [Resolver] Parent resolver (for recursive resolution)
        # @param options [Hash] Resolution options
        # @return [ResolutionResult]
        def resolve(did, parsed, _resolver, options = {})
          url = build_url(parsed.id)

          response = fetch_did_document(url, options)

          case response
          when Net::HTTPSuccess
            parse_response(did, response.body)
          when Net::HTTPNotFound
            ResolutionResult.not_found(did)
          else
            ResolutionResult.error("networkError", "HTTP #{response.code}: #{response.message}")
          end
        rescue URI::InvalidURIError => e
          ResolutionResult.invalid_did(did, "Invalid domain in DID: #{e.message}")
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
          ResolutionResult.error("networkError", "Connection failed: #{e.message}")
        rescue Net::OpenTimeout, Net::ReadTimeout => e
          ResolutionResult.error("networkError", "Request timeout: #{e.message}")
        rescue JSON::ParserError => e
          ResolutionResult.error("invalidDidDocument", "Invalid JSON in DID Document: #{e.message}")
        rescue StandardError => e
          ResolutionResult.error("internalError", e.message)
        end

        private

        # Build the HTTPS URL for the DID document
        # @param method_specific_id [String] The method-specific identifier
        # @return [String] The URL
        #
        # According to did:web spec:
        # - Colons in the method-specific-id separate path segments
        # - Percent-encoded colons (%3A) represent literal colons (for port numbers)
        # - Example: did:web:example.com         -> https://example.com/.well-known/did.json
        # - Example: did:web:example.com:users   -> https://example.com/users/did.json
        # - Example: did:web:localhost%3A8080    -> https://localhost:8080/.well-known/did.json
        #
        def build_url(method_specific_id)
          # First, split on unencoded colons to get path parts
          parts = method_specific_id.split(":")

          # Decode percent-encoded colons in each part (these are literal colons, e.g., port)
          decoded_parts = parts.map { |p| p.gsub("%3A", ":").gsub("%3a", ":") }

          # First part is the domain (possibly with port from decoded %3A)
          domain = decoded_parts.first

          # Remaining parts form the path
          path_parts = decoded_parts[1..]

          if path_parts.empty?
            # No path -> use .well-known
            "https://#{domain}/.well-known/did.json"
          else
            # Path specified -> use path/did.json
            path = path_parts.join("/")
            "https://#{domain}/#{path}/did.json"
          end
        end

        # Fetch the DID document from the URL
        def fetch_did_document(url, options = {})
          uri = URI.parse(url)
          timeout = options[:timeout] || DEFAULT_TIMEOUT

          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = (uri.scheme == "https")
          http.open_timeout = timeout
          http.read_timeout = timeout

          # Some servers require a proper User-Agent
          headers = {
            "Accept" => "application/did+ld+json, application/json",
            "User-Agent" => "DidResolver/#{VERSION} Ruby/#{RUBY_VERSION}"
          }

          request = Net::HTTP::Get.new(uri.request_uri, headers)
          http.request(request)
        end

        # Parse the response body as a DID Document
        def parse_response(did, body)
          data = JSON.parse(body)

          # Validate the document ID matches the DID
          doc_id = data["id"]
          unless doc_id == did
            return ResolutionResult.error(
              "invalidDidDocument",
              "DID Document id '#{doc_id}' does not match DID '#{did}'"
            )
          end

          did_document = DIDDocument.from_hash(data)

          ResolutionResult.success(
            did_document,
            document_metadata: extract_metadata(data)
          )
        end

        def extract_metadata(data)
          metadata = {}

          # Extract common metadata fields if present
          metadata[:created] = data["created"] if data["created"]
          metadata[:updated] = data["updated"] if data["updated"]
          metadata[:deactivated] = data["deactivated"] if data.key?("deactivated")

          metadata
        end
      end
    end
  end
end
