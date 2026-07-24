# frozen_string_literal: true

require_relative 'enforcer'
require_relative 'job_argument'

module Olyx # :nodoc:
  module Guardrails
    module Rails
      # Adds opt-in guardrail enforcement for declared Active Job arguments.
      #
      #   class CompletionJob < ApplicationJob
      #     include Olyx::Guardrails::Rails::Job
      #     guardrails_input_arguments 0, :system_prompt
      #   end
      #
      # Declared arguments are evaluated immediately before +perform+.
      module Job
        def self.included(base) # :nodoc:
          base.extend(ClassMethods)
        end

        # Class methods added to an Active Job class.
        module ClassMethods
          def guardrails_argument_selectors # :nodoc:
            return @guardrails_argument_selectors if defined?(@guardrails_argument_selectors)
            return superclass.guardrails_argument_selectors if superclass.respond_to?(:guardrails_argument_selectors)

            [].freeze
          end

          # :call-seq:
          #   guardrails_input_arguments(*selectors)
          #
          # Declares positional Integer indexes and keyword Symbol names to
          # evaluate before +perform+. The declaration requires at least one
          # non-negative Integer or Symbol. Missing selected arguments raise
          # ArgumentError when the job runs.
          def guardrails_input_arguments(*selectors)
            validate_guardrails_selectors!(selectors)
            @guardrails_argument_selectors = selectors.freeze
            before_perform { |job| job.send(:guardrails_enforce_arguments!) }
          end

          private

          def validate_guardrails_selectors!(selectors)
            valid = selectors.any? && selectors.all? { |selector| valid_guardrails_selector?(selector) }
            return if valid

            raise ArgumentError, 'job guardrail selectors must be non-negative Integers or Symbols'
          end

          def valid_guardrails_selector?(selector)
            selector.is_a?(Symbol) || (selector.is_a?(Integer) && selector >= 0)
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
