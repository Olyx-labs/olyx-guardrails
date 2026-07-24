# frozen_string_literal: true

require_relative 'constant_resolver'

module Olyx
  module Guardrails
    module Rails
      # Validates and resolves an Active Job class reference.
      class JobReference
        NAME = /\A[A-Z]\w*(?:::[A-Z]\w*)*\z/

        def initialize(job)
          @job = normalize(job)
        end

        def resolve
          target = @job.is_a?(String) ? ConstantResolver.call(@job) : @job
          return target if target.respond_to?(:perform_later)

          raise ArgumentError, 'configured job must respond to perform_later'
        end

        private

        def normalize(job)
          return job if job.respond_to?(:perform_later)

          name = job.to_s
          return name.freeze if (job.is_a?(String) || job.is_a?(Symbol)) && name.match?(NAME)

          raise ArgumentError, 'job must be an Active Job class or a constant name'
        end
      end
    end
  end
end
