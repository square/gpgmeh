# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "gpgmeh/version"

Gem::Specification.new do |spec|
  spec.name          = "gpgmeh"
  spec.version       = GPGMeh::VERSION
  spec.authors       = ["Andrew Lazarus"]
  spec.email         = ["lazarus@squareup.com"]

  spec.summary       = "GPG Made Even (Happier|Hipper|Harder?)"
  spec.homepage      = "https://stash.corp.squareup.com/projects/RUBY/repos/gpgmeh/browse"

  spec.metadata["allowed_push_host"] = "https://gems.vip.global.square/private/"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "activesupport", ">= 2.3"

  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "pry"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "0.40.0"
  spec.add_development_dependency "sq-gem_tasks", "~> 1.6"
end
