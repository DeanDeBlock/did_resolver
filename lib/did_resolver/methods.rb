# frozen_string_literal: true

# Load method resolvers
require_relative "methods/web"
require_relative "methods/key"
require_relative "methods/jwk"

module DidResolver
  # Methods namespace for DID method resolvers
  module Methods
  end
end
