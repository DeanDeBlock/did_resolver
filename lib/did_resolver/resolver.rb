# frozen_string_literal: true

module DidResolver
  # Universal DID Resolver
  #
  # Resolves DIDs by delegating to registered method resolvers.
  # Inspired by https://github.com/decentralized-identity/did-resolver
  #
  # @example
  #   resolver = Resolver.new(
  #     DidResolver::Methods::Web.resolver,
  #     DidResolver::Methods::Key.resolver
  #   )
  #   result = resolver.resolve("did:web:example.com")
  #
  class Resolver
    attr_reader :registry

    # @param method_resolvers [Array<Hash>] Method resolver hashes { method_name => resolve_proc }
    # @param cache [Cache, Boolean, nil] Cache implementation or true for default cache
    # @param logger [Logger, nil] Optional logger for error messages
    def initialize(*method_resolvers, cache: nil, logger: nil)
      @registry = {}
      @cache = build_cache(cache)
      @logger = logger

      # Register all provided method resolvers
      method_resolvers.flatten.each do |resolver_hash|
        register(resolver_hash)
      end
    end

    # Register a method resolver
    # @param resolver_hash [Hash] { method_name => resolve_proc }
    def register(resolver_hash)
      resolver_hash.each do |method_name, resolve_proc|
        @registry[method_name.to_s] = resolve_proc
      end
    end

    # Resolve a DID to its DID Document
    # @param did [String] The DID or DID URL to resolve
    # @param options [Hash] Resolution options
    # @option options [Boolean] :no_cache Skip cache lookup
    # @return [ResolutionResult]
    def resolve(did, **options)
      # Parse the DID
      parsed = ParsedDID.parse(did)

      # Check cache first (unless no_cache is set)
      if @cache && !options[:no_cache] && !parsed.params["no-cache"]
        cached = @cache.get(parsed.did)
        return cached if cached
      end

      # Find method resolver
      method_resolver = @registry[parsed.method]
      unless method_resolver
        return ResolutionResult.method_not_supported(parsed.method)
      end

      # Resolve
      result = method_resolver.call(parsed.did, parsed, self, options)

      # Cache successful results
      if @cache && !result.error? && result.did_document
        @cache.set(parsed.did, result)
      end

      result
    rescue InvalidDIDError => e
      ResolutionResult.invalid_did(did, e.message)
    rescue NotFoundError => e
      ResolutionResult.not_found(did)
    rescue NetworkError => e
      ResolutionResult.error("networkError", e.message)
    rescue StandardError => e
      @logger&.error("[DID Resolver] Unexpected error: #{e.message}")
      ResolutionResult.error("internalError", e.message)
    end

    # Check if a method is supported
    # @param method [String] DID method name
    # @return [Boolean]
    def supports?(method)
      @registry.key?(method.to_s)
    end

    # List supported methods
    # @return [Array<String>]
    def supported_methods
      @registry.keys
    end

    private

    def build_cache(cache_option)
      case cache_option
      when true
        Cache.new
      when Cache
        cache_option
      when nil, false
        nil
      else
        # Assume it's a custom cache implementation with get/set methods
        cache_option
      end
    end

    class << self
      # Default resolver with common methods registered
      # @return [Resolver]
      def default
        @default ||= new(
          Methods::Web.resolver,
          Methods::Key.resolver,
          Methods::Jwk.resolver,
          cache: true
        )
      end

      # Reset the default resolver (useful for testing)
      def reset_default!
        @default = nil
      end

      # Shortcut to resolve using default resolver
      def resolve(did, **options)
        default.resolve(did, **options)
      end
    end
  end
end
