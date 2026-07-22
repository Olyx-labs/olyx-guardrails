# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Measures adapter operations with a monotonic clock.
      module Timer
        module_function

        def call
          started = clock_time
          result = yield
          [result, elapsed_milliseconds(started)]
        end

        def clock_time
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end

        def elapsed_milliseconds(started)
          ((clock_time - started) * 1_000).round(3)
        end
        private_class_method :clock_time, :elapsed_milliseconds
      end
    end
  end
end
