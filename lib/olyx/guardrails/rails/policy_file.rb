# frozen_string_literal: true

require_relative '../policy'
require_relative 'policy_document'
require_relative 'policy_file_error'

module Olyx
  module Guardrails
    module Rails
      # Safely loads direct or environment-keyed policy YAML without ERB.
      class PolicyFile
        def self.load(path, environment:)
          new(path, environment).load
        end

        def initialize(path, environment)
          @path = path.to_s
          @environment = environment.to_s
        end

        def load
          Policy.from_h(PolicyDocument.new(@path, @environment).call)
        rescue Errno::ENOENT, Errno::EACCES, Psych::Exception, ArgumentError => error
          raise PolicyFileError.call(error, @path)
        end
      end
    end
  end
end
