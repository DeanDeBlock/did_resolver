# frozen_string_literal: true

require_relative "lib/did_resolver/version"

Gem::Specification.new do |spec|
  spec.name = "did_resolver"
  spec.version = DidResolver::VERSION
  spec.authors = ["Dean De Block"]
  spec.email = ["dean.de.block@gmail.com"]

  spec.summary = "Universal DID Resolver for Ruby"
  spec.description = <<~DESC
    A Ruby implementation of a universal DID (Decentralized Identifier) resolver,
    inspired by the Decentralized Identity Foundation's did-resolver.

    Supports multiple DID methods:
    - did:web - HTTPS domain-based DIDs
    - did:key - Self-describing cryptographic key DIDs
    - did:jwk - JWK-encoded DIDs

    Includes support for EBSI jwk_jcs-pub format (multicodec 0xeb51).
  DESC
  spec.homepage = "https://github.com/DeanDeBlock/did_resolver"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  spec.files = Dir.chdir(__dir__) do
    Dir["{lib,sig}/**/*", "LICENSE", "README.md", "CHANGELOG.md"].reject do |f|
      File.directory?(f)
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Runtime dependencies - keep minimal for gem extraction
  # No Rails dependency - pure Ruby
  spec.add_dependency "json", "~> 2.0"
  spec.add_dependency "base64", "~> 0.2"  # Required from Ruby 3.4.0+
  spec.add_dependency "uri", "~> 1.0"     # Required from Ruby 3.4.0+

  # Development dependencies
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.0"
  spec.add_development_dependency "webmock", "~> 3.0"
end
