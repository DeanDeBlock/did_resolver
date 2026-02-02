# frozen_string_literal: true

require "spec_helper"

RSpec.describe DidResolver::Methods::Key do
  describe ".resolve" do
    let(:resolver) { DidResolver::Resolver.new(described_class.resolver) }

    # Test Ed25519 key
    # This is a well-known test vector: z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
    context "with Ed25519 key" do
      let(:did) { "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" }

      it "resolves successfully" do
        result = resolver.resolve(did)

        expect(result.error?).to be false
        expect(result.did_document).not_to be_nil
        expect(result.did_document.id).to eq(did)
      end

      it "includes verification method with Ed25519 type" do
        result = resolver.resolve(did)
        doc = result.did_document

        expect(doc.verification_method.length).to eq(1)
        vm = doc.verification_method.first
        expect(vm["type"]).to eq("Ed25519VerificationKey2020")
        expect(vm["publicKeyMultibase"]).to start_with("z")
      end

      it "sets appropriate verification relationships" do
        result = resolver.resolve(did)
        doc = result.did_document

        expect(doc.authentication).not_to be_empty
        expect(doc.assertion_method).not_to be_empty
        expect(doc.key_agreement).to be_empty
      end
    end

    # Test EBSI jwk_jcs-pub format (multicodec 0xeb51)
    # This is the format used by EBSI/EU wallets
    context "with jwk_jcs-pub key (EBSI format)" do
      # This is a real EBSI DID with an embedded P-256 JWK
      let(:did) { "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbqWQ1ACSAtvNE1bRcFK77mWoiytZVrxF52YeUGMoEkohxCtSQ43PiZKkpfPnHVnrxbvcHXWiY11pXxFXt8NDJL7b4okxQD1ssrnNyig7VG7uhsXWmBW7Gqd2DuhoDzBr7fa" }

      it "resolves successfully" do
        result = resolver.resolve(did)

        expect(result.error?).to be false
        expect(result.did_document).not_to be_nil
        expect(result.did_document.id).to eq(did)
      end

      it "includes verification method with JsonWebKey2020 type" do
        result = resolver.resolve(did)
        doc = result.did_document

        expect(doc.verification_method.length).to eq(1)
        vm = doc.verification_method.first
        expect(vm["type"]).to eq("JsonWebKey2020")
        expect(vm["publicKeyJwk"]).to be_a(Hash)
      end

      it "extracts the embedded JWK correctly" do
        result = resolver.resolve(did)
        vm = result.did_document.verification_method.first
        jwk = vm["publicKeyJwk"]

        expect(jwk["kty"]).to eq("EC")
        expect(jwk["crv"]).to eq("P-256")
        expect(jwk["x"]).not_to be_nil
        expect(jwk["y"]).not_to be_nil
      end

      it "sets all verification relationships" do
        result = resolver.resolve(did)
        doc = result.did_document

        expect(doc.authentication).not_to be_empty
        expect(doc.assertion_method).not_to be_empty
        expect(doc.capability_invocation).not_to be_empty
        expect(doc.capability_delegation).not_to be_empty
      end
    end

    context "with unsupported multibase prefix" do
      let(:did) { "did:key:f1234567890" } # 'f' is base16, not supported

      it "returns an error" do
        result = resolver.resolve(did)

        expect(result.error?).to be true
        expect(result.error).to eq("invalidDid")
      end
    end

    context "with unsupported multicodec" do
      # This is a made-up key with an unsupported multicodec
      # Using base58btc encoding of [0xff, 0xff, ...some bytes...]
      it "returns an error for unknown key type" do
        # Create a did:key with an unsupported multicodec prefix
        result = resolver.resolve("did:key:z11111111111111111")

        expect(result.error?).to be true
        expect(result.error).to eq("invalidDid")
      end
    end
  end

  describe ".resolver" do
    it "returns a hash with 'key' key" do
      resolver = described_class.resolver

      expect(resolver).to be_a(Hash)
      expect(resolver).to have_key("key")
      expect(resolver["key"]).to respond_to(:call)
    end
  end
end
