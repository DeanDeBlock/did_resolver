# frozen_string_literal: true

require "spec_helper"

RSpec.describe DidResolver do
  it "has a version number" do
    expect(DidResolver::VERSION).not_to be_nil
  end

  describe DidResolver::ParsedDID do
    describe ".parse" do
      it "parses a simple DID" do
        parsed = described_class.parse("did:web:example.com")

        expect(parsed.did).to eq("did:web:example.com")
        expect(parsed.method).to eq("web")
        expect(parsed.id).to eq("example.com")
        expect(parsed.path).to be_nil
        expect(parsed.fragment).to be_nil
      end

      it "parses a DID with path" do
        parsed = described_class.parse("did:web:example.com:users:alice")

        expect(parsed.did).to eq("did:web:example.com:users:alice")
        expect(parsed.method).to eq("web")
        expect(parsed.id).to eq("example.com:users:alice")
      end

      it "parses a DID with fragment" do
        parsed = described_class.parse("did:key:z6MkhaXgBZDvotDkL#key-1")

        expect(parsed.did).to eq("did:key:z6MkhaXgBZDvotDkL")
        expect(parsed.fragment).to eq("#key-1")
      end

      it "parses a DID with query" do
        parsed = described_class.parse("did:web:example.com?service=hub")

        expect(parsed.params).to eq("service" => "hub")
      end

      it "raises for invalid DID format" do
        expect { described_class.parse("not-a-did") }.to raise_error(DidResolver::InvalidDIDError)
        expect { described_class.parse("") }.to raise_error(DidResolver::InvalidDIDError)
        expect { described_class.parse(nil) }.to raise_error(DidResolver::InvalidDIDError)
      end

      it "normalizes method name to lowercase" do
        parsed = described_class.parse("did:WEB:example.com")
        expect(parsed.method).to eq("web")
      end
    end
  end

  describe DidResolver::Resolver do
    describe "#resolve" do
      it "returns method not supported for unknown methods" do
        resolver = described_class.new

        result = resolver.resolve("did:unknown:12345")

        expect(result.error?).to be true
        expect(result.error).to eq("methodNotSupported")
      end

      it "returns invalid DID for malformed DIDs" do
        resolver = described_class.new

        result = resolver.resolve("not-a-did")

        expect(result.error?).to be true
        expect(result.error).to eq("invalidDid")
      end
    end

    describe "#supports?" do
      it "returns true for registered methods" do
        resolver = described_class.new(DidResolver::Methods::Key.resolver)

        expect(resolver.supports?("key")).to be true
        expect(resolver.supports?("web")).to be false
      end
    end

    describe "#supported_methods" do
      it "lists all registered methods" do
        resolver = described_class.new(
          DidResolver::Methods::Key.resolver,
          DidResolver::Methods::Jwk.resolver
        )

        expect(resolver.supported_methods).to contain_exactly("key", "jwk")
      end
    end

    describe ".default" do
      it "returns a resolver with all built-in methods" do
        resolver = described_class.default

        expect(resolver.supports?("web")).to be true
        expect(resolver.supports?("key")).to be true
        expect(resolver.supports?("jwk")).to be true
      end
    end
  end

  describe DidResolver::DIDDocument do
    describe ".from_hash" do
      it "parses a DID Document" do
        data = {
          "@context" => ["https://www.w3.org/ns/did/v1"],
          "id" => "did:example:123",
          "verificationMethod" => [
            {
              "id" => "did:example:123#key-1",
              "type" => "JsonWebKey2020",
              "controller" => "did:example:123",
              "publicKeyJwk" => { "kty" => "EC", "crv" => "P-256" }
            }
          ],
          "authentication" => ["did:example:123#key-1"]
        }

        doc = described_class.from_hash(data)

        expect(doc.id).to eq("did:example:123")
        expect(doc.verification_method).to be_an(Array)
        expect(doc.verification_method.first["id"]).to eq("did:example:123#key-1")
      end
    end

    describe "#find_verification_method" do
      let(:doc) do
        described_class.new(
          id: "did:example:123",
          verification_method: [
            { "id" => "did:example:123#key-1", "type" => "JsonWebKey2020" },
            { "id" => "did:example:123#key-2", "type" => "Ed25519VerificationKey2020" }
          ]
        )
      end

      it "finds by full ID" do
        vm = doc.find_verification_method("did:example:123#key-1")
        expect(vm["type"]).to eq("JsonWebKey2020")
      end

      it "finds by fragment reference" do
        vm = doc.find_verification_method("#key-2")
        expect(vm["type"]).to eq("Ed25519VerificationKey2020")
      end

      it "returns nil for unknown ID" do
        vm = doc.find_verification_method("did:example:123#unknown")
        expect(vm).to be_nil
      end
    end

    describe "#to_h" do
      it "serializes to a hash with correct keys" do
        doc = described_class.new(
          id: "did:example:123",
          verification_method: [
            { "id" => "did:example:123#key-1", "type" => "JsonWebKey2020" }
          ],
          authentication: ["did:example:123#key-1"]
        )

        hash = doc.to_h

        expect(hash["id"]).to eq("did:example:123")
        expect(hash["@context"]).to include("https://www.w3.org/ns/did/v1")
        expect(hash["verificationMethod"]).to be_an(Array)
        expect(hash["authentication"]).to eq(["did:example:123#key-1"])
      end
    end
  end

  describe DidResolver::Cache do
    it "caches and retrieves results" do
      cache = described_class.new
      result = DidResolver::ResolutionResult.success(
        DidResolver::DIDDocument.new(id: "did:test:123")
      )

      cache.set("did:test:123", result)

      expect(cache.get("did:test:123")).to eq(result)
    end

    it "expires entries after TTL" do
      cache = described_class.new(ttl: 0.1)
      result = DidResolver::ResolutionResult.success(
        DidResolver::DIDDocument.new(id: "did:test:123")
      )

      cache.set("did:test:123", result)
      sleep 0.2

      expect(cache.get("did:test:123")).to be_nil
    end

    it "can delete specific entries" do
      cache = described_class.new
      result = DidResolver::ResolutionResult.success(
        DidResolver::DIDDocument.new(id: "did:test:123")
      )

      cache.set("did:test:123", result)
      cache.delete("did:test:123")

      expect(cache.get("did:test:123")).to be_nil
    end

    it "can clear all entries" do
      cache = described_class.new
      result = DidResolver::ResolutionResult.success(
        DidResolver::DIDDocument.new(id: "did:test:123")
      )

      cache.set("did:test:123", result)
      cache.set("did:test:456", result)
      cache.clear

      expect(cache.size).to eq(0)
    end
  end

  describe DidResolver::ResolutionResult do
    describe ".success" do
      it "creates a successful result" do
        doc = DidResolver::DIDDocument.new(id: "did:test:123")
        result = described_class.success(doc)

        expect(result.error?).to be false
        expect(result.did_document).to eq(doc)
        expect(result.content_type).to eq("application/did+ld+json")
      end
    end

    describe ".error" do
      it "creates an error result" do
        result = described_class.error("notFound", "DID not found")

        expect(result.error?).to be true
        expect(result.error).to eq("notFound")
        expect(result.error_message).to eq("DID not found")
        expect(result.did_document).to be_nil
      end
    end

    describe ".not_found" do
      it "creates a not found error" do
        result = described_class.not_found("did:test:123")

        expect(result.error?).to be true
        expect(result.error).to eq("notFound")
      end
    end

    describe ".method_not_supported" do
      it "creates a method not supported error" do
        result = described_class.method_not_supported("foobar")

        expect(result.error?).to be true
        expect(result.error).to eq("methodNotSupported")
      end
    end
  end
end
