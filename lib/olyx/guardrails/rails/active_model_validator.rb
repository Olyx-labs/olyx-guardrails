# frozen_string_literal: true

require 'active_model'

# Validates an explicitly declared Active Model attribute with Olyx Guardrails.
#
#   validates :prompt, olyx_guardrails: true
#
# By default the validator uses finalized Rails configuration. Pass
# <tt>olyx_guardrails: { policy: policy }</tt> to use a core Policy directly.
class OlyxGuardrailsValidator < ActiveModel::EachValidator
  # Evaluates +value+ and adds an error to +record+ and +attribute+ when the
  # active policy rejects it. Active Model calls this method.
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
