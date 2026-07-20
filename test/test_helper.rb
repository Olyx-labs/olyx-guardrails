# frozen_string_literal: true

if ENV["COVERAGE"] == "true"
  require "simplecov"

  SimpleCov.start do
    enable_coverage :branch
    cover "lib/**/*.rb"
    minimum_coverage line: 95, branch: 80
  end
end

require "minitest/autorun"
require "minitest/mock"
require_relative "../lib/olyx/guardrails"
