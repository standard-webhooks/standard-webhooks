
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = "standardwebhooks"
  spec.version       = "1.0.0"
  spec.authors       = ["Standard Webhooks"]
  spec.license       = "MIT"

  spec.summary       = "Ruby library for creating and verifying webhook signatures."

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["allowed_push_host"] = "https://rubygems.org"
    spec.metadata["source_code_uri"] = "https://github.com/standard-webhooks/standard-webhooks"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  # Specify which files should be added to the gem when it is released.
  ignored = Regexp.union(
    /\Aspec/,
    /\Apkg/,
    /\Atemplates/,
    /\A.gitignore/,
    /.gem\z/
  )

  spec.files = Dir['**/*'].reject {|f| !File.file?(f) || ignored.match(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", ">= 2.2.10"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.2"
end
