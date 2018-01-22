# coding: utf-8
# frozen_string_literal: true

lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "gpgmeh/version"

Gem::Specification.new do |spec|
  spec.name          = "gpgmeh"
  spec.version       = GPGMeh::VERSION
  spec.authors       = ["Andrew Lazarus"]
  spec.email         = ["lazarus@squareup.com"]

  spec.summary       = "GPG Made Even (Happier|Hipper|Harder?)"
  spec.homepage      = "https://github.com/square/gpgmeh"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "activesupport", ">= 2.3"
  spec.add_dependency "nio4r", "~> 2.2"
end
