# frozen_string_literal: true

require_relative 'configuration'

module Olyx
  module Guardrails
    module Rails
      # Owns the Rails adapter's boot configuration lifecycle.
      class ConfigurationRegistry
        attr_reader :configuration

        def initialize
          @configuration = Configuration.new
        end

        def configure
          yield configuration
          configuration
        end

        def finalize!(environment:)
          configuration.finalize!(environment: environment)
        end

        def ready
          finalize!(environment: current_environment) unless configuration.finalized?
          configuration.ensure_enabled!
          configuration
        end

        private

        def current_environment
          return ::Rails.env if defined?(::Rails) && ::Rails.respond_to?(:env)

          ENV.fetch('RAILS_ENV', 'development')
        end
      end
    end
  end
end
