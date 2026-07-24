# frozen_string_literal: true

module Olyx
  module Guardrails
    module Notification
      # Constructs the notifier's validated policy and delivery dispatcher.
      module NotifierSetup
        module_function

        def call(policy, handlers)
          config = NotifierConfiguration.new(policy: policy, handlers: handlers)
          configured_policy = config.policy
          sanitizer = NotificationSanitizer.new(configured_policy)
          [configured_policy, DeliveryDispatcher.new(config.handlers, sanitizer)]
        end
      end
    end
  end
end
