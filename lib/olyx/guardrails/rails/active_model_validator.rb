# frozen_string_literal: true

require 'active_model'

# Explicit Active Model validator for AI-bound text attributes.
class OlyxGuardrailsValidator < ActiveModel::EachValidator
  def validate_each(record, attribute, value)
    result = evaluate(record, attribute, value)
    return if result[:allowed]

    record.errors.add(attribute, options.fetch(:message, 'was rejected by guardrail policy'))
  end

  private

  def evaluate(record, attribute, value)
    policy = options[:policy]
    return Olyx::Guardrails.check(value, policy: policy) if policy

    metadata = { model: record.class.name, attribute: attribute }
    Olyx::Guardrails::Rails.check(value, metadata: metadata)
  end
end
