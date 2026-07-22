# frozen_string_literal: true

require 'rails/railtie'

module Olyx
  module Guardrails
    # Boots and validates the optional Rails adapter.
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
