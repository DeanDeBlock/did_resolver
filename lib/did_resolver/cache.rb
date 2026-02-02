# frozen_string_literal: true

module DidResolver
  # Simple in-memory cache for DID resolution results
  #
  # For production use with long-running processes, consider using
  # a cache with TTL support (e.g., Redis, Memcached).
  #
  class Cache
    DEFAULT_TTL = 300 # 5 minutes

    def initialize(ttl: DEFAULT_TTL)
      @store = {}
      @ttl = ttl
    end

    # Get a cached resolution result
    # @param did [String] The DID
    # @return [ResolutionResult, nil]
    def get(did)
      entry = @store[did]
      return nil unless entry

      if entry[:expires_at] && Time.now > entry[:expires_at]
        @store.delete(did)
        return nil
      end

      entry[:result]
    end

    # Cache a resolution result
    # @param did [String] The DID
    # @param result [ResolutionResult] The resolution result
    def set(did, result, ttl: nil)
      expires_at = if ttl || @ttl
        Time.now + (ttl || @ttl)
      end

      @store[did] = {
        result: result,
        expires_at: expires_at,
        cached_at: Time.now
      }
    end

    # Remove a cached entry
    # @param did [String] The DID
    def delete(did)
      @store.delete(did)
    end

    # Clear all cached entries
    def clear
      @store.clear
    end

    # Number of cached entries
    def size
      cleanup_expired
      @store.size
    end

    private

    def cleanup_expired
      now = Time.now
      @store.delete_if do |_did, entry|
        entry[:expires_at] && now > entry[:expires_at]
      end
    end
  end
end
