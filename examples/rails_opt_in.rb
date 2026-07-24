# frozen_string_literal: true

# Copy the relevant sections into a Rails application. Nothing is scanned
# globally: each helper is called at an application-owned AI boundary.

require 'olyx/guardrails/rails'

# config/initializers/olyx_guardrails.rb
# Configuration is finalized after initialization and must not be mutated per
# request. Choose either policy_path or an inline policy, never both.
Olyx::Guardrails::Rails.configure(
  enabled: true,
  policy_path: Rails.root.join('config/olyx_guardrails.yml'),
  llm_provider: nil,
  notifier_handlers: {
    # Handlers are synchronous; enqueue here when delivery may block.
    audit: ->(event) { Rails.logger.warn(event.inspect) }
  },
  # These names are added to Rails parameter filtering; they are not scan hooks.
  filter_parameters: %i[prompt system_prompt llm_input]
)

# Controller input, redaction, and completed-output enforcement.
class AiRequestsController < ApplicationController
  include Olyx::Guardrails::Rails::Controller

  rescue_from Olyx::Guardrails::Blocked do |error|
    render json: { error: 'input_rejected', decision: error.decision },
           status: :unprocessable_entity
  end

  def create
    prompt = params.require(:prompt)
    # Decide before model invocation, then redact into a separate value.
    guardrails_check!(prompt, metadata: { account_id: current_account.id })
    safe_prompt = guardrails_redact(prompt)[:text]
    completion = LlmClient.complete(safe_prompt)
    # Output enforcement applies to the completed response, not streamed tokens.
    Olyx::Guardrails::Rails::Enforcer.check_output!(completion)
    render json: { completion: completion }, status: :created
  end
end

# GraphQL resolver or mutation.
class CompletionResolver
  include Olyx::Guardrails::Rails::GraphQL

  def resolve(prompt:)
    guardrails_check_graphql!(prompt)
    completion = LlmClient.complete(prompt)
    guardrails_check_graphql_output!(completion)
    { completion: completion }
  end
end

# Action Cable channel.
class PromptChannel < ApplicationCable::Channel
  include Olyx::Guardrails::Rails::ActionCable

  def receive(data)
    guardrails_check_cable!(data.fetch('prompt'))
    transmit(status: 'accepted')
  end
end

# Active Job arguments are checked immediately before perform.
class CompletionJob < ApplicationJob
  include Olyx::Guardrails::Rails::Job

  # Select positional arguments by index and keyword arguments by name.
  guardrails_input_arguments 0, :system_prompt

  def perform(prompt, system_prompt:)
    LlmClient.complete(prompt, system_prompt: system_prompt)
  end
end

# Active Model validation for an explicitly declared AI-bound attribute.
class PromptDraft
  include ActiveModel::Model

  attr_accessor :prompt

  validates :prompt, olyx_guardrails: true
end

# Caller-owned upload parsing. The extractor must return a String.
class UploadedPromptChecker
  def self.call(upload)
    # Guardrails does not infer file type, parse documents, or set extraction
    # limits; the application-owned extractor is the trust boundary.
    Olyx::Guardrails::Rails::Upload.check!(
      upload,
      extractor: ->(file) { DocumentTextExtractor.call(file.tempfile) }
    )
  end
end

# Service objects, callbacks, and custom transports use the reusable enforcer.
class ConversationService
  def self.call(messages)
    # Helpers are opt-in; including a Rails adapter does not scan other paths.
    Olyx::Guardrails::Rails::Enforcer.check_messages!(
      messages,
      metadata: { boundary: 'conversation_service' }
    )
    LlmClient.chat(messages)
  end
end
