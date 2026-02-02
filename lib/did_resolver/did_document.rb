# frozen_string_literal: true

module DidResolver
  # DID Document representation
  # @see https://www.w3.org/TR/did-core/#did-document-properties
  class DIDDocument
    attr_reader :id, :also_known_as, :controller, :verification_method,
                :authentication, :assertion_method, :key_agreement,
                :capability_invocation, :capability_delegation, :service,
                :context, :extra

    def initialize(
      id:,
      context: nil,
      also_known_as: nil,
      controller: nil,
      verification_method: nil,
      authentication: nil,
      assertion_method: nil,
      key_agreement: nil,
      capability_invocation: nil,
      capability_delegation: nil,
      service: nil,
      **extra
    )
      @id = id
      @context = context || ["https://www.w3.org/ns/did/v1"]
      @also_known_as = also_known_as
      @controller = controller
      @verification_method = verification_method || []
      @authentication = authentication || []
      @assertion_method = assertion_method || []
      @key_agreement = key_agreement || []
      @capability_invocation = capability_invocation || []
      @capability_delegation = capability_delegation || []
      @service = service || []
      @extra = extra
    end

    # Find a verification method by ID or reference
    # @param id_or_ref [String] Full ID or fragment reference
    # @return [VerificationMethod, nil]
    def find_verification_method(id_or_ref)
      # Normalize reference - could be full ID or just fragment
      target_id = id_or_ref.start_with?("#") ? "#{@id}#{id_or_ref}" : id_or_ref

      verification_method.find { |vm| vm[:id] == target_id || vm["id"] == target_id }
    end

    # Get verification methods for a specific purpose
    # @param purpose [Symbol] :authentication, :assertion_method, etc.
    # @return [Array<VerificationMethod>]
    def verification_methods_for(purpose)
      refs = send(purpose)
      return [] unless refs

      refs.map do |ref|
        if ref.is_a?(String)
          find_verification_method(ref)
        else
          ref
        end
      end.compact
    end

    # Extract public key from a verification method
    # @param method_id [String] Verification method ID
    # @return [Hash, nil] Public key info with :type and :key
    def public_key_for(method_id)
      vm = find_verification_method(method_id)
      return nil unless vm

      extract_public_key(vm)
    end

    # Get the first public key for a purpose (e.g., assertion)
    # @param purpose [Symbol]
    # @return [Hash, nil]
    def first_public_key_for(purpose)
      vms = verification_methods_for(purpose)
      return nil if vms.empty?

      extract_public_key(vms.first)
    end

    def to_h
      result = {
        "@context" => @context,
        "id" => @id
      }

      result["alsoKnownAs"] = @also_known_as if @also_known_as&.any?
      result["controller"] = @controller if @controller
      result["verificationMethod"] = @verification_method if @verification_method&.any?
      result["authentication"] = @authentication if @authentication&.any?
      result["assertionMethod"] = @assertion_method if @assertion_method&.any?
      result["keyAgreement"] = @key_agreement if @key_agreement&.any?
      result["capabilityInvocation"] = @capability_invocation if @capability_invocation&.any?
      result["capabilityDelegation"] = @capability_delegation if @capability_delegation&.any?
      result["service"] = @service if @service&.any?

      # Merge any extra properties
      result.merge(@extra.transform_keys(&:to_s))
    end

    def to_json(*)
      to_h.to_json
    end

    class << self
      # Parse a DID Document from a hash
      # @param data [Hash] The raw DID Document data
      # @return [DIDDocument]
      def from_hash(data)
        data = data.transform_keys { |k| underscore(k.to_s).to_sym }

        new(
          id: data[:id],
          context: data[:@context] || data[:context],
          also_known_as: data[:also_known_as],
          controller: data[:controller],
          verification_method: normalize_verification_methods(data[:verification_method]),
          authentication: data[:authentication],
          assertion_method: data[:assertion_method],
          key_agreement: data[:key_agreement],
          capability_invocation: data[:capability_invocation],
          capability_delegation: data[:capability_delegation],
          service: data[:service],
          **data.reject { |k, _|
            %i[id @context context also_known_as controller
               verification_method authentication assertion_method
               key_agreement capability_invocation capability_delegation service].include?(k)
          }
        )
      end

      private

      # Convert camelCase to snake_case
      def underscore(str)
        str.gsub(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
           .gsub(/([a-z\d])([A-Z])/, '\1_\2')
           .downcase
      end

      def normalize_verification_methods(methods)
        return [] unless methods

        methods.map do |vm|
          vm.is_a?(Hash) ? vm.transform_keys(&:to_s) : vm
        end
      end
    end

    private

    def extract_public_key(vm)
      vm = vm.transform_keys(&:to_s) if vm.is_a?(Hash)

      type = vm["type"]
      key_data = nil

      # Handle different key formats
      if vm["publicKeyJwk"]
        key_data = { format: :jwk, value: vm["publicKeyJwk"] }
      elsif vm["publicKeyMultibase"]
        key_data = { format: :multibase, value: vm["publicKeyMultibase"] }
      elsif vm["publicKeyBase58"]
        key_data = { format: :base58, value: vm["publicKeyBase58"] }
      elsif vm["publicKeyHex"]
        key_data = { format: :hex, value: vm["publicKeyHex"] }
      elsif vm["publicKeyPem"]
        key_data = { format: :pem, value: vm["publicKeyPem"] }
      end

      return nil unless key_data

      {
        id: vm["id"],
        type: type,
        controller: vm["controller"],
        **key_data
      }
    end
  end
end
