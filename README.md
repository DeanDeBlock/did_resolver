# DID Resolver

A Ruby library for resolving Decentralized Identifiers (DIDs) according to the [W3C DID Core specification](https://www.w3.org/TR/did-core/).

Inspired by the Decentralized Identity Foundation's [did-resolver](https://github.com/decentralized-identity/did-resolver) JavaScript library.

## Features

- **Pluggable Architecture**: Easily add support for new DID methods
- **Built-in Method Resolvers**:
  - `did:web` - Resolve DIDs from web domains
  - `did:key` - Self-describing DIDs with embedded public keys
  - `did:jwk` - DIDs with embedded JWK (JSON Web Key)
- **Caching**: Optional in-memory caching with TTL support
- **Standards Compliant**: Follows W3C DID Core specification for resolution results
- **EBSI Support**: Supports `jwk_jcs-pub` multicodec (0xeb51) for EBSI compatibility

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'did_resolver'
```

And then execute:

```bash
$ bundle install
```

Or install it yourself as:

```bash
$ gem install did_resolver
```

## Usage

### Basic Usage

```ruby
require 'did_resolver'

# Resolve a DID using the default resolver
result = DidResolver::Resolver.resolve("did:web:example.com")

if result.error?
  puts "Error: #{result.error_message}"
else
  puts result.did_document.to_h
end
```

### Custom Resolver Configuration

```ruby
require 'did_resolver'

# Create a resolver with specific methods and caching
resolver = DidResolver::Resolver.new(
  DidResolver::Methods::Web.resolver,
  DidResolver::Methods::Key.resolver,
  DidResolver::Methods::Jwk.resolver,
  cache: true  # Enable default in-memory cache
)

# Resolve a did:key
result = resolver.resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
did_document = result.did_document

# Access verification methods
did_document.verification_method.each do |vm|
  puts "Key ID: #{vm['id']}"
  puts "Type: #{vm['type']}"
end
```

### Working with DID Documents

```ruby
result = resolver.resolve("did:web:example.com")
doc = result.did_document

# Find a specific verification method
vm = doc.find_verification_method("#key-1")

# Get verification methods for a purpose
auth_keys = doc.verification_methods_for(:authentication)

# Extract public key info
key_info = doc.first_public_key_for(:assertion_method)
# => { id: "did:...#key-1", type: "JsonWebKey2020", format: :jwk, value: {...} }
```

### Supported DID Methods

#### did:web

Resolves DIDs from web domains by fetching `/.well-known/did.json` or a custom path.

```ruby
# Standard domain
resolver.resolve("did:web:example.com")
# => fetches https://example.com/.well-known/did.json

# With path
resolver.resolve("did:web:example.com:users:alice")
# => fetches https://example.com/users/alice/did.json

# With port
resolver.resolve("did:web:localhost%3A8080")
# => fetches https://localhost:8080/.well-known/did.json
```

#### did:key

Self-describing DIDs with the public key encoded in the identifier.

```ruby
# Ed25519 key
resolver.resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

# P-256 key
resolver.resolve("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169")

# EBSI jwk_jcs-pub format
resolver.resolve("did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrD...")
```

**Supported key types:**
- Ed25519 (0xed)
- X25519 (0xec)
- secp256k1 (0xe7)
- P-256 (0x1200)
- P-384 (0x1201)
- P-521 (0x1202)
- RSA (0x1205)
- jwk_jcs-pub (0xeb51) - EBSI format

#### did:jwk

DIDs with a base64url-encoded JWK as the identifier.

```ruby
# EC P-256 key
jwk = { "kty" => "EC", "crv" => "P-256", "x" => "...", "y" => "..." }
encoded = Base64.urlsafe_encode64(jwk.to_json, padding: false)
resolver.resolve("did:jwk:#{encoded}")
```

### Caching

```ruby
# Use default cache (5 minute TTL)
resolver = DidResolver::Resolver.new(
  DidResolver::Methods::Web.resolver,
  cache: true
)

# Custom TTL
cache = DidResolver::Cache.new(ttl: 3600)  # 1 hour
resolver = DidResolver::Resolver.new(
  DidResolver::Methods::Web.resolver,
  cache: cache
)

# Skip cache for a specific resolution
result = resolver.resolve("did:web:example.com", no_cache: true)
```

### Creating Custom Method Resolvers

```ruby
module DidResolver
  module Methods
    class MyMethod
      class << self
        def resolver
          { "mymethod" => method(:resolve) }
        end

        def resolve(did, parsed, resolver, options = {})
          # parsed.did    - the base DID
          # parsed.method - "mymethod"
          # parsed.id     - method-specific identifier

          # Your resolution logic here...
          did_document = DIDDocument.new(id: did, ...)

          ResolutionResult.success(did_document)
        rescue => e
          ResolutionResult.error("internalError", e.message)
        end
      end
    end
  end
end

# Register the custom resolver
resolver = DidResolver::Resolver.new(
  DidResolver::Methods::MyMethod.resolver
)
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests.

```bash
bundle install
bundle exec rake spec
bundle exec rubocop
```

## Contributing

Bug reports and pull requests are welcome on GitHub.

## License

The gem is available as open source under the terms of the [Apache License 2.0](https://opensource.org/licenses/Apache-2.0).
