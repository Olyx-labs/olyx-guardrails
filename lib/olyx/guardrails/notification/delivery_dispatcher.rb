# frozen_string_literal: true

module Olyx
  module Guardrails
    module Notification
      # Isolates handler failures and produces immutable delivery summaries.
      class DeliveryDispatcher
        def initialize(handlers, sanitizer)
          @handlers = handlers
          @sanitizer = sanitizer
        end

        def call(event)
          deliveries = @handlers.map { |name, handler| deliver(name, handler, event) }.freeze
          success = deliveries.all? { |delivery| delivery[:success] }
          { success: success, event: event, deliveries: deliveries }.freeze
        end

        def failure(error)
          { success: false, error: safe_error(error), deliveries: [].freeze }.freeze
        end

        private

        def deliver(name, handler, event)
          handler.call(event)
          { handler: name, success: true }.freeze
        rescue StandardError => error
          { handler: name, success: false, error: safe_error(error) }.freeze
        end

        def safe_error(error)
          @sanitizer.field(error.message)
        rescue StandardError
          'notification failure'
        end
      end
    end
  end
end
