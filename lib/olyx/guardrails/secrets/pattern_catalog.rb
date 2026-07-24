# frozen_string_literal: true

require_relative 'cloud_credential_patterns'
require_relative 'generic_credential_patterns'
require_relative 'network_patterns'

module Olyx
  module Guardrails
    module Secrets
      # Declarative catalog for built-in confidentiality and credential forms.
      module PatternCatalog
        MARKERS = [
          'confidential', 'proprietary', 'restricted', 'internal use only',
          'not for distribution', 'do not share', 'do not distribute', 'top secret',
          'trade secret', 'need to know', 'company confidential',
          'attorney-client privilege', 'attorney client privilege', 'work product',
          'privileged and confidential'
        ].freeze
        CONFIDENTIALITY = MARKERS.map do |marker|
          Regexp.new(Regexp.escape(marker), Regexp::IGNORECASE)
        end.freeze
        SIMPLE = {
          'private_network_address' => NetworkPatterns::PRIVATE_IP,
          'aws_access_key' => CloudCredentialPatterns::AWS_ACCESS_KEY,
          'aws_secret_key' => CloudCredentialPatterns::AWS_SECRET_KEY,
          'secret_token' => GenericCredentialPatterns::TOKEN,
          'jwt' => GenericCredentialPatterns::JWT,
          'private_key' => GenericCredentialPatterns::PRIVATE_KEY,
          'database_url' => GenericCredentialPatterns::DATABASE_URL,
          'stripe_key' => CloudCredentialPatterns::STRIPE_KEY,
          'google_key' => CloudCredentialPatterns::GOOGLE_KEY,
          'azure_storage_key' => CloudCredentialPatterns::AZURE_STORAGE_KEY
        }.freeze
      end
    end
  end
end
