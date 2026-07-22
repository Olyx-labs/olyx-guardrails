# frozen_string_literal: true

# Copy the relevant sections into a Rails application. Nothing is scanned
# globally: each helper is called at an application-owned AI boundary.

require 'olyx/guardrails/rails'

# config/initializers/olyx_guardrails.rb
Olyx::Guardrails::Rails.configure do |config|
  config.enabled = true
  config.policy_path = Rails.root.join('config/olyx_guardrails.yml')
  config.ai_analyzer = nil
  config.notifier_handlers = {
    audit: ->(event) { Rails.logger.warn(event.inspect) }
  }
  config.filter_parameters = %i[prompt system_prompt ai_input llm_input]
end

# Controller input, redaction, and completed-output enforcement.
class AiRequestsController < ApplicationController
  include Olyx::Guardrails::Rails::Controller

  rescue_from Olyx::Guardrails::Blocked do |error|
    render json: { error: 'input_rejected', decision: error.decision },
           status: :unprocessable_entity
  end

  def create
    prompt = params.require(:prompt)
    guardrails_check!(prompt, metadata: { account_id: current_account.id })
    safe_prompt = guardrails_redact(prompt)[:text]
    completion = LlmClient.complete(safe_prompt)
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
    Olyx::Guardrails::Rails::Upload.check!(
      upload,
      extractor: ->(file) { DocumentTextExtractor.call(file.tempfile) }
    )
  end
end

# Service objects, callbacks, and custom transports use the reusable enforcer.
class ConversationService
  def self.call(messages)
    Olyx::Guardrails::Rails::Enforcer.check_messages!(
      messages,
      metadata: { boundary: 'conversation_service' }
    )
    LlmClient.chat(messages)
  end
end
