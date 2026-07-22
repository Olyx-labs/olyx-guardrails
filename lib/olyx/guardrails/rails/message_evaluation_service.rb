# frozen_string_literal: true

require_relative '../message_source'
require_relative 'decision_service'

module Olyx
  module Guardrails
    module Rails
      # Evaluates structured messages with Rails telemetry and notifications.
      MessageEvaluationService = DecisionService.new(:check_messages, notification_input: MessageSource)
    end
  end
end
