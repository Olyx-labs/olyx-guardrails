# frozen_string_literal: true

module Olyx
  module Guardrails
    module Notification
      # Builds an immutable aggregate handler-delivery result.
      module DeliverySummary
        module_function

        def call(event, deliveries)
          success = deliveries.all? { |delivery| delivery[:success] }
          { success: success, event: event, deliveries: deliveries }.freeze
        end
      end
    end
  end
end
