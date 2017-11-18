# frozen_string_literal: true

require "spec_helper"
require "benchmark"

RSpec.describe "GPGMeh stress test:" do
  THREADS = 100
  ITERS = 50

  around do |example|
    time = Benchmark.realtime { example.call }
    description = example.metadata[:description]
    description.replace(format(description, time * 1_000 / THREADS / ITERS, THREADS, ITERS))
  end

  it(+"%.1f ms / roundtip encrypt, decrypt iteration (threads=%d, iters=%d)") do
    threads = Array.new(THREADS) do
      spiff = SUPPORT.join("spacemanspiff").to_s
      Thread.new do
        ITERS.times do
          encrypted_blob = GPGMeh.encrypt(
            "boom", %w[7CAAAB91], gpg_options: { timeout_sec: 300 }
          ) { |_| "test" }

          GPGMeh.decrypt(
            encrypted_blob,
            gpg_options: { homedir: spiff, timeout_sec: 300 }
          ) { |_short_sub_key_id| "test" }
        end
      end
    end
    expect { threads.each(&:join) }.not_to raise_error
  end
end
