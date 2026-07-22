# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Builds bounded request identity metadata from a controller instance.
      module ControllerMetadata
        module_function

        def call(controller)
          request = controller.request
          {
            request_id: request.request_id,
            controller: controller.controller_name,
            action: controller.action_name,
            http_method: request.request_method
          }
        end
      end
    end
  end
end
