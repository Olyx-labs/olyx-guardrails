# frozen_string_literal: true

require_relative 'instrumentation'

module Olyx
  module Guardrails
    module Rails
      # Dispatches optional Rails notifications without coupling evaluation.
      module NotificationDispatcher
        module_function

        def call(configuration, result, input, metadata)
          notifier = configuration.notifier
          return unless notifier

          delivery = notifier.notify(result, input: input, metadata: metadata)
          Instrumentation.publish_notification(delivery) if delivery
        end
      end
    end
  end
end
