# frozen_string_literal: true

require_relative 'enforcer'
require_relative 'job_argument'

module Olyx
  module Guardrails
    module Rails
      # Opt-in Active Job callback for declared AI-input arguments.
      module Job
        def self.included(base)
          base.extend(ClassMethods)
        end

        # Class-level declaration for protected argument indexes or keyword names.
        module ClassMethods
          attr_reader :guardrails_argument_selectors

          def guardrails_input_arguments(*selectors)
            @guardrails_argument_selectors = selectors.freeze
            before_perform { |job| job.send(:guardrails_enforce_arguments!) }
          end
        end

        private

        def guardrails_enforce_arguments!
          job_class = self.class
          job_class.guardrails_argument_selectors.each do |selector|
            input = JobArgument.call(arguments, selector)
            Enforcer.check!(input, metadata: { job: job_class.name, argument: selector })
          end
        end
      end
    end
  end
end
