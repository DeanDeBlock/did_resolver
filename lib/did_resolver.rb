# frozen_string_literal: true

# DID Resolver Library
#
# A Ruby implementation inspired by the Decentralized Identity Foundation's
# did-resolver (https://github.com/decentralized-identity/did-resolver)
#
# This library provides a universal interface for resolving Decentralized
# Identifiers (DIDs) according to the W3C DID Core specification.
#
# Usage:
#   require 'did_resolver'
#
#   # Create a resolver with method resolvers
#   resolver = DidResolver::Resolver.new(
#     DidResolver::Methods::Web.resolver,
#     DidResolver::Methods::Key.resolver,
#     DidResolver::Methods::Jwk.resolver
#   )
#
#   # Resolve a DID
#   result = resolver.resolve("did:web:example.com")
#   result.did_document # => DIDDocument
#
# Method Resolver Implementation:
#   Each method resolver exports a .resolver method returning { method_name: resolve_proc }
#   The resolve_proc receives (did, parsed, resolver, options) and returns a DIDResolutionResult
#
module DidResolver
  class Error < StandardError; end
  class InvalidDIDError < Error; end
  class UnsupportedMethodError < Error; end
  class ResolutionError < Error; end
  class NotFoundError < ResolutionError; end
  class NetworkError < ResolutionError; end

  # DID Resolution Result as per DID Core spec
  # @see https://www.w3.org/TR/did-core/#did-resolution
  class ResolutionResult
    attr_reader :did_resolution_metadata, :did_document, :did_document_metadata

    def initialize(did_document: nil, did_resolution_metadata: {}, did_document_metadata: {})
      @did_document = did_document
      @did_resolution_metadata = did_resolution_metadata.freeze
      @did_document_metadata = did_document_metadata.freeze
    end

    def error?
      !did_resolution_metadata[:error].nil? && did_resolution_metadata[:error] != ""
    end

    def error
      did_resolution_metadata[:error]
    end

    def error_message
      did_resolution_metadata[:error_message]
    end

    def content_type
      did_resolution_metadata[:content_type] || "application/did+ld+json"
    end

    def to_h
      {
        did_resolution_metadata: did_resolution_metadata,
        did_document: did_document&.to_h,
        did_document_metadata: did_document_metadata
      }
    end

    # Factory methods for common results
    class << self
      def success(did_document, metadata: {}, document_metadata: {})
        new(
          did_document: did_document,
          did_resolution_metadata: { content_type: "application/did+ld+json" }.merge(metadata),
          did_document_metadata: document_metadata
        )
      end

      def error(error_type, message = nil)
        new(
          did_resolution_metadata: {
            error: error_type,
            error_message: message
          }.compact
        )
      end

      def not_found(did)
        error("notFound", "DID not found: #{did}")
      end

      def method_not_supported(method)
        error("methodNotSupported", "DID method not supported: #{method}")
      end

      def invalid_did(did, reason = nil)
        error("invalidDid", reason || "Invalid DID format: #{did}")
      end
    end
  end

  # Parsed DID components
  # @see https://www.w3.org/TR/did-core/#did-syntax
  class ParsedDID
    attr_reader :did, :method, :id, :path, :query, :fragment, :params

    # DID Syntax: did:method-name:method-specific-id
    DID_REGEX = /\Adid:([a-z0-9]+):([^#?\/]+)(\/[^#?]*)?(\\?[^#]*)?(#.*)?\z/i.freeze

    def initialize(did:, method:, id:, path: nil, query: nil, fragment: nil, params: {})
      @did = did
      @method = method
      @id = id
      @path = path
      @query = query
      @fragment = fragment
      @params = params.freeze
    end

    # The full DID URL (did + path + query + fragment)
    def did_url
      @did_url ||= "#{did}#{path}#{query}#{fragment}"
    end

    def to_h
      {
        did: did,
        method: method,
        id: id,
        path: path,
        query: query,
        fragment: fragment,
        params: params
      }.compact
    end

    class << self
      # Parse a DID string into components
      # @param did_string [String] The DID or DID URL to parse
      # @return [ParsedDID]
      # @raise [InvalidDIDError] if the DID format is invalid
      def parse(did_string)
        raise InvalidDIDError, "DID cannot be nil" if did_string.nil?
        raise InvalidDIDError, "DID cannot be empty" if did_string.empty?

        # Normalize and extract parts
        did_string = did_string.strip

        match = did_string.match(DID_REGEX)
        raise InvalidDIDError, "Invalid DID format: #{did_string}" unless match

        method = match[1].downcase
        id = match[2]
        path = match[3]
        query = match[4]
        fragment = match[5]

        # Extract DID parameters from query if present
        params = parse_params(query)

        # The base DID (without path, query, fragment)
        base_did = "did:#{method}:#{id}"

        new(
          did: base_did,
          method: method,
          id: id,
          path: path,
          query: query,
          fragment: fragment,
          params: params
        )
      end

      private

      def parse_params(query_string)
        return {} unless query_string

        # Remove leading ?
        query_string = query_string[1..] if query_string.start_with?("?")
        return {} if query_string.empty?

        query_string.split("&").each_with_object({}) do |pair, hash|
          key, value = pair.split("=", 2)
          hash[key] = value
        end
      end
    end
  end
end

# Load sub-modules
require_relative "did_resolver/version"
require_relative "did_resolver/did_document"
require_relative "did_resolver/resolver"
require_relative "did_resolver/cache"
require_relative "did_resolver/methods"
