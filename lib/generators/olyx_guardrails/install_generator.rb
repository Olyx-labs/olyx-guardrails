# frozen_string_literal: true

require 'rails/generators/base'

module OlyxGuardrails
  module Generators
    # Installs explicit, environment-specific Rails policy configuration.
    class InstallGenerator < ::Rails::Generators::Base
      source_root File.expand_path('templates', __dir__)

      desc 'Install Olyx Guardrails Rails configuration and policies'

      def copy_initializer
        template 'initializer.rb.tt', 'config/initializers/olyx_guardrails.rb'
      end

      def copy_policy
        template 'policy.yml.tt', 'config/olyx_guardrails.yml'
      end
    end
  end
end
