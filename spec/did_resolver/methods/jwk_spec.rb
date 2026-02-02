# frozen_string_literal: true

require "spec_helper"

RSpec.describe DidResolver::Methods::Jwk do
  describe ".resolve" do
    let(:resolver) { DidResolver::Resolver.new(described_class.resolver) }

    context "with P-256 EC key" do
      let(:jwk) do
        {
          "kty" => "EC",
          "crv" => "P-256",
          "x" => "WKn-ZIGevcwGFOMJ0GeEei2HHfBxpW3h9mOmyD4BmFU",
          "y" => "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        }
      end
      let(:encoded_jwk) { Base64.urlsafe_encode64(jwk.to_json, padding: false) }
      let(:did) { "did:jwk:#{encoded_jwk}" }

      it "resolves successfully" do
        result = resolver.resolve(did)

        expect(result.error?).to be false
        expect(result.did_document).not_to be_nil
        expect(result.did_document.id).to eq(did)
      end

      it "includes verification method with JWK" do
        result = resolver.resolve(did)
        doc = result.did_document

        expect(doc.verification_method.length).to eq(1)
        vm = doc.verification_method.first
        expect(vm["type"]).to eq("JsonWebKey2020")
        expect(vm["publicKeyJwk"]).to be_a(Hash)
        expect(vm["publicKeyJwk"]["kty"]).to eq("EC")
        expect(vm["publicKeyJwk"]["crv"]).to eq("P-256")
      end

      it "sets appropriate verification relationships for signing curve" do
        result = resolver.resolve(did)
        doc = result.did_document

        expect(doc.authentication).not_to be_empty
        expect(doc.assertion_method).not_to be_empty
        expect(doc.key_agreement).not_to be_empty # P-256 also supports ECDH
      end
    end

    context "with Ed25519 OKP key" do
      let(:jwk) do
        {
          "kty" => "OKP",
          "crv" => "Ed25519",
          "x" => "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }
      end
      let(:encoded_jwk) { Base64.urlsafe_encode64(jwk.to_json, padding: false) }
      let(:did) { "did:jwk:#{encoded_jwk}" }

      it "resolves successfully" do
        result = resolver.resolve(did)

        expect(result.error?).to be false
        expect(result.did_document.id).to eq(did)
      end

      it "sets signing relationships but not key agreement" do
        result = resolver.resolve(did)
        doc = result.did_document

        expect(doc.authentication).not_to be_empty
        expect(doc.assertion_method).not_to be_empty
        expect(doc.key_agreement).to be_empty
      end
    end

    context "with X25519 key agreement key" do
      let(:jwk) do
        {
          "kty" => "OKP",
          "crv" => "X25519",
          "x" => "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
        }
      end
      let(:encoded_jwk) { Base64.urlsafe_encode64(jwk.to_json, padding: false) }
      let(:did) { "did:jwk:#{encoded_jwk}" }

      it "only sets key agreement relationship" do
        result = resolver.resolve(did)
        doc = result.did_document

        expect(doc.key_agreement).not_to be_empty
        expect(doc.authentication).to be_empty
        expect(doc.assertion_method).to be_empty
      end
    end

    context "with invalid JWK" do
      it "returns error for invalid base64" do
        result = resolver.resolve("did:jwk:not-valid-base64!!!")

        expect(result.error?).to be true
      end

      it "returns error for missing kty" do
        bad_jwk = { "crv" => "P-256" }
        encoded = Base64.urlsafe_encode64(bad_jwk.to_json, padding: false)

        result = resolver.resolve("did:jwk:#{encoded}")

        expect(result.error?).to be true
        expect(result.error_message).to include("kty")
      end

      it "returns error for unsupported key type" do
        bad_jwk = { "kty" => "oct", "k" => "secret" }
        encoded = Base64.urlsafe_encode64(bad_jwk.to_json, padding: false)

        result = resolver.resolve("did:jwk:#{encoded}")

        expect(result.error?).to be true
        expect(result.error_message).to include("Unsupported")
      end
    end
  end

  describe ".resolver" do
    it "returns a hash with 'jwk' key" do
      resolver = described_class.resolver

      expect(resolver).to be_a(Hash)
      expect(resolver).to have_key("jwk")
      expect(resolver["jwk"]).to respond_to(:call)
    end
  end
end
