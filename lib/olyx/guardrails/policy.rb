# frozen_string_literal: true

require_relative 'policy/configuration_hash'
require_relative 'policy/configuration'

module Olyx
  module Guardrails
    # Immutable enforcement configuration for decisions and transformations.
    class Policy
      def self.default
        @default ||= new
      end

      def self.from_h(config)
        new(**PolicyComponents::ConfigurationHash.call(config))
      end

      def initialize(
        name: 'default',
        max_input_length: 10_000,
        block_pii: false,
        block_injections: true,
        block_secrets: false,
        ai_failure_mode: :allow,
        secret_patterns: [],
        rules: []
      )
        @configuration = PolicyComponents::Configuration.new(
          identity: [name, max_input_length],
          blocking: [block_pii, block_injections, block_secrets],
          restrictions: [ai_failure_mode, secret_patterns, rules]
        )
        freeze
      end

      def name = @configuration.identity.name
      def max_input_length = @configuration.identity.max_input_length
      def ai_failure_mode = @configuration.restrictions.ai_failure_mode
      def secret_patterns = @configuration.restrictions.secret_patterns
      def rules = @configuration.restrictions.rules
      def block_pii? = @configuration.blocking.pii?
      def block_injections? = @configuration.blocking.injections?
      def block_secrets? = @configuration.blocking.secrets?
    end
  end
end
