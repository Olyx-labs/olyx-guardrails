# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Normalizes an optional Active Job queue name.
      module QueueName
        module_function

        def call(queue)
          return nil if queue.nil?

          name = queue.to_s
          return name.freeze if (queue.is_a?(String) || queue.is_a?(Symbol)) && !name.empty?

          raise ArgumentError, 'queue must be a non-empty String or Symbol'
        end
      end
    end
  end
end
