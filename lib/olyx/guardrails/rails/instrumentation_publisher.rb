# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Publishes Active Support events and isolates observability failures.
      module InstrumentationPublisher
        module_function

        def call(name, payload)
          ActiveSupport::Notifications.instrument(name, payload)
        rescue StandardError => error
          logger = rails_logger
          logger&.warn("Olyx Guardrails instrumentation #{name} failed (#{error.class})")
        end

        def rails_logger
          ::Rails.logger if defined?(::Rails) && ::Rails.respond_to?(:logger)
        end
        private_class_method :rails_logger
      end
    end
  end
end
