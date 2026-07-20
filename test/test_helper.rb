# frozen_string_literal: true

if ENV["COVERAGE"] == "true"
  require "simplecov"

  SimpleCov.start do
    enable_coverage :branch
    cover "lib/**/*.rb"
    minimum_coverage line: 40, branch: 10
  end
end

require "minitest/autorun"
require "minitest/mock"
require_relative "../lib/olyx/guardrails"
