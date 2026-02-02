# frozen_string_literal: true

require "spec_helper"

RSpec.describe DidResolver::Methods::Web do
  describe "URL building" do
    it "builds correct URL for simple domain" do
      url = described_class.send(:build_url, "example.com")
      expect(url).to eq("https://example.com/.well-known/did.json")
    end

    it "builds correct URL for domain with path" do
      url = described_class.send(:build_url, "example.com:users:alice")
      expect(url).to eq("https://example.com/users/alice/did.json")
    end

    it "decodes percent-encoded port" do
      url = described_class.send(:build_url, "localhost%3A8080")
      expect(url).to eq("https://localhost:8080/.well-known/did.json")
    end

    it "handles domain with port and path" do
      url = described_class.send(:build_url, "localhost%3A8080:api:v1")
      expect(url).to eq("https://localhost:8080/api/v1/did.json")
    end
  end

  describe ".resolver" do
    it "returns a hash with 'web' key" do
      resolver = described_class.resolver

      expect(resolver).to be_a(Hash)
      expect(resolver).to have_key("web")
      expect(resolver["web"]).to respond_to(:call)
    end
  end

  describe "integration with Resolver" do
    let(:resolver) { DidResolver::Resolver.new(described_class.resolver) }

    it "supports did:web method" do
      expect(resolver.supports?("web")).to be true
    end

    context "with mocked HTTP responses" do
      let(:did) { "did:web:example.com" }
      let(:did_document) do
        {
          "@context" => ["https://www.w3.org/ns/did/v1"],
          "id" => did,
          "verificationMethod" => [
            {
              "id" => "#{did}#key-1",
              "type" => "JsonWebKey2020",
              "controller" => did,
              "publicKeyJwk" => { "kty" => "EC", "crv" => "P-256" }
            }
          ]
        }
      end

      before do
        stub_request(:get, "https://example.com/.well-known/did.json")
          .to_return(
            status: 200,
            body: did_document.to_json,
            headers: { "Content-Type" => "application/json" }
          )
      end

      it "resolves the DID document" do
        result = resolver.resolve(did)

        expect(result.error?).to be false
        expect(result.did_document.id).to eq(did)
        expect(result.did_document.verification_method.first["id"]).to eq("#{did}#key-1")
      end
    end

    context "with 404 response" do
      before do
        stub_request(:get, "https://notfound.example.com/.well-known/did.json")
          .to_return(status: 404)
      end

      it "returns not found error" do
        result = resolver.resolve("did:web:notfound.example.com")

        expect(result.error?).to be true
        expect(result.error).to eq("notFound")
      end
    end

    context "with mismatched document ID" do
      before do
        stub_request(:get, "https://mismatch.example.com/.well-known/did.json")
          .to_return(
            status: 200,
            body: { "id" => "did:web:other.com" }.to_json,
            headers: { "Content-Type" => "application/json" }
          )
      end

      it "returns invalid document error" do
        result = resolver.resolve("did:web:mismatch.example.com")

        expect(result.error?).to be true
        expect(result.error).to eq("invalidDidDocument")
      end
    end
  end

  describe "response parsing" do
    it "parses valid DID document" do
      data = {
        "@context" => ["https://www.w3.org/ns/did/v1"],
        "id" => "did:web:example.com",
        "verificationMethod" => [
          {
            "id" => "did:web:example.com#key-1",
            "type" => "JsonWebKey2020",
            "controller" => "did:web:example.com",
            "publicKeyJwk" => { "kty" => "EC", "crv" => "P-256" }
          }
        ]
      }

      result = described_class.send(:parse_response, "did:web:example.com", data.to_json)

      expect(result.error?).to be false
      expect(result.did_document.id).to eq("did:web:example.com")
    end

    it "rejects document with mismatched ID" do
      data = {
        "@context" => ["https://www.w3.org/ns/did/v1"],
        "id" => "did:web:other.com"
      }

      result = described_class.send(:parse_response, "did:web:example.com", data.to_json)

      expect(result.error?).to be true
      expect(result.error).to eq("invalidDidDocument")
    end
  end
end
