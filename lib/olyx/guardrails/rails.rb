# frozen_string_literal: true

require 'active_support/notifications'
require 'forwardable'
require_relative '../guardrails'
require_relative 'rails/active_job_handler'
require_relative 'rails/action_cable'
require_relative 'rails/active_model_validator'
require_relative 'rails/controller'
require_relative 'rails/enforcer'
require_relative 'rails/graphql'
require_relative 'rails/job'
require_relative 'rails/runtime'
require_relative 'rails/upload'

module Olyx
  module Guardrails
    # Optional Rails-native configuration and enforcement facade.
    module Rails
      extend SingleForwardable

      def self.runtime
        @runtime ||= Runtime.new
      end
      private_class_method :runtime

      def_single_delegators :runtime,
                            :configuration, :configure, :finalize!,
                            :check, :redact, :check_messages,
                            :check_output, :redact_output
    end
  end
end

require_relative 'railtie' if defined?(Rails::Railtie)
