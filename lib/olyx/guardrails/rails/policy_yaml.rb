# frozen_string_literal: true

require 'yaml'

module Olyx
  module Guardrails
    module Rails
      # Safely reads a YAML policy document without aliases or object types.
      module PolicyYaml
        module_function

        def load(path)
          document = YAML.safe_load_file(path, permitted_classes: [], permitted_symbols: [], aliases: false,
                                               filename: path)
          return document if document.is_a?(Hash)

          raise ConfigurationError, "guardrail policy file must contain a Hash: #{path}"
        end
      end
    end
  end
end
