# frozen_string_literal: true

require 'rails/railtie'

module Olyx # :nodoc:
  module Guardrails
    # Integrates Olyx Guardrails with the Rails initialization lifecycle.
    #
    # The Railtie adds configured parameter filters after application
    # initializers and finalizes guardrail configuration in +after_initialize+.
    class Railtie < ::Rails::Railtie
      initializer 'olyx_guardrails.filter_parameters', after: :load_config_initializers do |app|
        filters = Guardrails::Rails.configuration.filter_parameters
        app.config.filter_parameters.concat(filters).uniq!
      end

      config.after_initialize do
        Guardrails::Rails.finalize!(environment: ::Rails.env)
      end
    end
  end
end
