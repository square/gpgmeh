require "active_support/core_ext/object/blank"
require "active_support/core_ext/object/try"
require "logger"
require "open3"
require "io/wait"

class GPGMeh
  class Error < StandardError; end
  class TimeoutError < Error; end
  class NoPassphraseError < Error; end
end

require "gpgmeh/key"
require "gpgmeh/version"

class GPGMeh
  # Encrypt message using public key encryption for the `recipients`
  #
  # @param plaintext [String] bytes to be encrypted with the recipient(s)'
  #   public key; each recipient's secret key must be used to decrypt the message
  # @param recipients [String] or [Array<String>] list of public key id's
  # @param gpg_options [Hash<Symbol, String>] gpg options, valid keys: cmd, args, homedir
  #   cmd: gpg command to execute, default=gpg
  #   args: command line arguments for gpg, default=%w(--armor --trust-model always)
  #     (note: --no-tty and --quiet are always added)
  #   homedir: custom homedir for gpg (passes --homedir argument to gpg)
  # @param sign [bool] should the encrypted message be signed? Requires `passphrase_callback`. [default=true]
  # @param passphrase_callback [callable] or [block] callable that returns the secret keyring passphrase,
  #   only required when signing; the callable takes an 8 character string argument (short format key id)
  #
  # @return [String] encrypted message
  #
  # Example:
  #
  #   GPGMeh.encrypt("boom", "ABC123DE") do |secret_key_id|
  #     if secret_key_id == "123ABC45"
  #       "secret_keyring1_passphrase"
  #     else
  #       "secret_keyring2_passphrase"
  #     end
  #   end
  #
  def self.encrypt(plaintext, recipients, gpg_options: {}, sign: true, passphrase_callback: nil, &block)
    raise ArgumentError, "passphrase callback required to sign" if sign && (passphrase_callback || block).nil?
    raise ArgumentError, "recipient(s) required" if recipients.empty?
    unless recipients.all? { |key_id| /^[A-Za-z0-9]+$/ =~ key_id }
      raise ArgumentError, "recipient key ids must all be alphanumeric strings"
    end
    new(gpg_options).encrypt(plaintext, recipients, sign: sign, passphrase_callback: passphrase_callback || block)
  end

  # Decrypt public key encrypted message using secret keyring
  #
  # @param encrypted_blob [String] encrypted blob to decrypt
  # @param gpg_options (@see #GPGMeh.encrypt)
  # @param passphrase_callback (@see #GPGMeh.encrypt)
  #
  # @return [String] encrypted message
  def self.decrypt(encrypted_blob, gpg_options: {}, passphrase_callback: nil, &block)
    raise ArgumentError, "passphrase callback required" if (passphrase_callback || block).nil?
    new(gpg_options).decrypt(encrypted_blob, passphrase_callback || block)
  end

  # Encrypt message using a symmetric passphrase
  #
  # @param plaintext (@see #GPGMeh.encrypt)
  # @param gpg_options (@see #GPGMeh.encrypt)
  # @param sign (@see #GPGMeh.encrypt)
  # @param passphrase_callback [callable] or [block] callable that returns passphrases:
  #   `callable.call(:symmetric)` # => the symmetric passphrase (required)
  #   `callable.call(<short format secret key id>)` # => the secret keyring passphrase
  #     (optional, only used when signing)
  #
  # Example:
  #
  #   GPGMeh.encrypt_symmetric("boom") do |secret_key_id|
  #     if secret_key_id == :symmetric
  #       "my-symmetric-secret"
  #     elsif secret_key_id == "123ABC45"
  #       "secret_keyring1_passphrase"
  #     else
  #       "secret_keyring2_passphrase"
  #     end
  #   end
  #
  # @return [String] encrypted message
  def self.encrypt_symmetric(
    plaintext,
    gpg_options: {},
    sign: true,
    passphrase_callback: nil,
    &block
  )
    new(gpg_options).encrypt_symmetric(
      plaintext,
      sign: sign,
      passphrase_callback: passphrase_callback || block,
    )
  end

  def self.public_keys(gpg_options: {})
    new(gpg_options).public_keys
  end

  def self.secret_keys(gpg_options: {})
    new(gpg_options).secret_keys
  end

  def self.version(gpg_options: {})
    new(gpg_options).version
  end

  class <<self
    attr_accessor :default_cmd, :default_args, :default_homedir, :timeout_sec
    attr_writer :logger
  end
  self.default_cmd = "gpg".freeze
  self.default_args = %w(--armor --trust-model always).freeze
  self.timeout_sec = 0.2

  def self.logger
    @logger ||= Logger.new(STDOUT)
  end

  def initialize(
    cmd: self.class.default_cmd,
    args: self.class.default_args,
    homedir: self.class.default_homedir
  )
    @gpg_cmd = cmd.dup
    @gpg_args = args.dup
    @gpg_args.concat(["--homedir", homedir.dup]) if homedir
    @gpg_args << "--no-tty" unless @gpg_args.include?("--no-tty")
    @gpg_args << "--quiet" unless @gpg_args.include?("--quiet")
    @deadline = Time.now + self.class.timeout_sec
  end
  private_class_method :new

  private

  attr_reader :gpg_cmd, :gpg_args, :status_r, :status_w, :command_r, :command_w

  def start_subprocess(extra_args, input = nil, callback = nil)
    if callback
      @status_r, @status_w = IO.pipe
      status_w.close_on_exec = false
      @command_r, @command_w = IO.pipe
      command_r.close_on_exec = false
      command_w.sync = true
      extra_args.concat(["--status-fd", status_w.to_i.to_s, "--command-fd", command_r.to_i.to_s])
    end

    Open3.popen3(gpg_cmd, *gpg_args, *extra_args, close_others: !callback) do |stdin, stdout, stderr, wait_thread|
      stdout.set_encoding(Encoding::BINARY)
      begin
        if callback
          command_r.close
          status_w.close
        end

        if input
          stdin.write(input)
          stdin.close
        end

        handle_gpg_fd_io(callback) if callback
      rescue => e
        self.class.logger.error("GPGMeh: error=#{e.inspect} backtrace=#{e.backtrace.inspect}")
        begin
          Process.kill(:SIGINT, wait_thread.pid)
        rescue
          nil
        end
        raise
      end

      warning = read_nonblock(stderr)
      if warning.present?
        self.class.logger.warn("GPGMeh: gpg stderr=#{warning.inspect}")
      end
      # wait on thread completion until the deadline
      raise TimeoutError if wait_thread.join(@deadline - Time.now).nil?
      if wait_thread.value.try(:success?)
        read_nonblock(stdout)
      else
        raise Error, "gpg non-zero exit status=#{wait_thread.value}"
      end
    end
  end

  def handle_gpg_fd_io(callback)
    buffer = ""
    read_nonblock(status_r) do |status_chunk|
      buffer += status_chunk
      last = buffer.rindex("\n")

      buffer[0..last].split("\n").each do |line|
        if /NEED_PASSPHRASE (?<sub_key_id>\S+) (?<key_id>\S+)/ =~ line
          if ENV["GPG_DEBUG"]
            self.class.logger.debug("GPGMeh: sub_key_id=#{sub_key_id.inspect} key_id=#{key_id.inspect}")
          end
          passphrase = callback.call(sub_key_id[-8..-1])
          raise NoPassphraseError, "secret keyring passphrase required from callback" unless passphrase
          command_w.puts(passphrase)
        elsif /NEED_PASSPHRASE_SYM/ =~ line
          passphrase = callback.call(:symmetric)
          raise NoPassphraseError, "symmetric passphrase required from callback" unless passphrase
          command_w.puts(passphrase)
        end
      end
      buffer = buffer[(last + 1)..-1]
    end
  ensure
    status_r.close
    command_w.close
  end

  # If a block is given, all partial reads of the io will be passed sequentially to the block.
  # Returns everything read on the stream up until an EOF is read, or throws TimeoutError
  # if there is no EOF before the deadline.
  def read_nonblock(io)
    output = ""
    loop do
      raise TimeoutError if Time.now >= @deadline

      output_chunk = io.read_nonblock(8192, exception: false)
      self.class.logger.debug("GPGMeh: output=#{output_chunk.inspect}") if ENV["GPG_DEBUG"]

      return output if output_chunk.nil? # only returned for EOF error?

      if output_chunk == :wait_readable
        wait = @deadline - Time.now
        raise TimeoutError if 0 >= wait
        io.wait_readable(wait)
        next
      end

      yield output_chunk if block_given?

      output += output_chunk
    end
  end

  # These methods are "public", but since `new` is private, they should be inaccessible
  public

  # @private
  def encrypt(plaintext, recipients, sign:, passphrase_callback:)
    extra_args = %w(--encrypt) + recipients.flat_map { |recipient| ["--recipient", recipient] }
    extra_args << "--sign" if sign
    start_subprocess(extra_args, plaintext, passphrase_callback)
  end

  # @private
  def decrypt(encrypted_blob, passphrase_callback)
    start_subprocess(["--decrypt"], encrypted_blob, passphrase_callback)
  end

  # @private
  def encrypt_symmetric(plaintext, sign:, passphrase_callback:)
    extra_args = ["--symmetric"]
    extra_args << "--sign" if sign

    start_subprocess(extra_args, plaintext, passphrase_callback)
  end

  # @private
  def public_keys
    Key.parse(start_subprocess(%w(--with-colons --list-public-keys)))
  end

  # @private
  def secret_keys
    Key.parse(start_subprocess(%w(--with-colons --list-secret-keys)))
  end

  # @private
  def version
    start_subprocess(%w(--version))
  end
end
