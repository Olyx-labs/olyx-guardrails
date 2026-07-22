# frozen_string_literal: true

require_relative 'job_reference'
require_relative 'queue_name'

module Olyx
  module Guardrails
    module Rails
      # Adapts immutable notification events to any Active Job-compatible job.
      class ActiveJobHandler
        def initialize(job:, queue: nil)
          @job = JobReference.new(job)
          @queue = QueueName.call(queue)
          freeze
        end

        def call(event)
          raise ArgumentError, 'Active Job notification event must be a Hash' unless event.is_a?(Hash)

          target = @job.resolve
          target = target.set(queue: @queue) if @queue
          target.perform_later(event)
        end
      end
    end
  end
end
