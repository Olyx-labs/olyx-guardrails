# frozen_string_literal: true

require_relative 'job_reference'
require_relative 'queue_name'

module Olyx # :nodoc:
  module Guardrails
    module Rails
      # Enqueues sanitized notification events through an Active Job class.
      #
      # A String or Symbol job name resolves at delivery time, making it safe
      # for Rails code reloading.
      class ActiveJobHandler
        # :call-seq:
        #   ActiveJobHandler.new(job:, queue: nil) -> ActiveJobHandler
        #
        # Builds and freezes a handler. +job+ is an Active Job class or a
        # String/Symbol constant name. +queue+ is an optional non-empty String
        # or Symbol.
        def initialize(job:, queue: nil)
          @job = JobReference.new(job)
          @queue = QueueName.call(queue)
          freeze
        end

        # :call-seq:
        #   handler.call(event)
        #
        # Enqueues +event+ with +perform_later+. +event+ must be a Hash. The
        # resolved job target must respond to +perform_later+.
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
