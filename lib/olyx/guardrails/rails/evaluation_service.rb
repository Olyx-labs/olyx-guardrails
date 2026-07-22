# frozen_string_literal: true

require_relative 'decision_service'

module Olyx
  module Guardrails
    module Rails
      # Runs one configured text decision and its post-decision integrations.
      EvaluationService = DecisionService.new(:check)
    end
  end
end
