require "spec_helper"
require "benchmark"

RSpec.describe "GPGMeh stress test:" do
  THREADS = 100
  ITERS = 50

  around do |example|
    tmp = GPGMeh.passphrase_timeout_sec
    GPGMeh.passphrase_timeout_sec = 10

    time = Benchmark.realtime { example.call }

    GPGMeh.passphrase_timeout_sec = tmp

    description = example.metadata[:description]
    description.replace(description % [time * 1_000 / THREADS / ITERS, THREADS, ITERS])
  end

  it "%.1f ms / roundtip encrypt, decrypt iteration (threads=%d, iters=%d)" do
    threads = THREADS.times.map do
      spiff = SUPPORT.join("spacemanspiff").to_s
      Thread.new do
        ITERS.times do
          encrypted_blob = GPGMeh.encrypt("boom", %w(7CAAAB91)) { |_| "test" }
          GPGMeh.decrypt(
            encrypted_blob,
            gpg_options: {homedir: spiff},
          ) { |_short_sub_key_id| "test" }
        end
      end
    end
    expect { threads.each(&:join) }.not_to raise_error
  end
end
