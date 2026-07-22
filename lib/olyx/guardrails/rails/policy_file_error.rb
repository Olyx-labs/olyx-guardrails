# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Translates policy loading failures into stable boot configuration errors.
      module PolicyFileError
        module_function

        def call(error, path)
          ConfigurationError.new(message(error, path))
        end

        def message(error, path)
          return "guardrail policy file does not exist: #{path}" if error.is_a?(Errno::ENOENT)
          return "guardrail policy file is not readable: #{path}" if error.is_a?(Errno::EACCES)
          return "guardrail policy file contains invalid or unsafe YAML: #{path}" if error.is_a?(Psych::Exception)

          "invalid guardrail policy in #{path}: #{error.message}"
        end
        private_class_method :message
      end
    end
  end
end
