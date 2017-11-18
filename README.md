# GPGMeh: GPG Made Even _HARDER_!

[![Build Status](https://travis-ci.org/square/gpgmeh.svg?branch=master)](https://travis-ci.org/square/gpgmeh)

## Why?

GPG can be complicated: this gem is just a high level wrapper around `gpg`.
GPGME also provides a nice API on top of GPG, but it has two drawbacks: it is
not thread safe and it holds the GIL when shelling out to `gpg`. This holds up
the entire ruby process for the duration of the GPG call, which can be
relatively slow.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'gpgmeh'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install gpgmeh

## Usage

### Default Configuration

```ruby
GPGMeh.default_cmd = "gpg" # first gpg found in your $PATH
GPGMeh.default_args = ["--armor", "--trust-model", "always"]` # --no-tty` and `--quiet` are always added to the argument list
GPGMeh.timeout_sec = 0.2 # wait up to 200ms for gpg to finish
```

### Troubleshooting your Configuration

Make sure `GPGMeh.default_cmd` uses `gpg`, *not* `gpg2`. If you get any of the following errors, check your `gpg` version.

`gpg2` has a slightly different format for `--list-keys --with-colons`:

```
lib/gpgmeh/key.rb:74:in `rescue in creation_date=': invalid date="1454695279" (GPGMeh::Key::ParseError)
```

`gpg2` may have trouble starting the agent:

```
command get_passphrase failed: Inappropriate ioctl for device
```


### Public Key Encryption: Rick wants to encrypt and sign something for Spiff

```ruby
# 7CAAAB91 is Spaceman Spiff's public key id; multiple recipients can be specified
GPGMeh.encrypt("boom", ["7CAAAB91"]) do |key_id|
  # This is the passphrase callback. The argument is Rick's secret key id.
  # Return value: the secret keyring passphrase
  "rick's-secret-keyring-passphrase"
end
```

### Public Key Decryption: Spiff wants to decrypt something from Rick

```ruby
encrypted_message = <<EOM
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

hQEMA5IgSfURq0FaAQf/TxrcB0EeC5XpEwVyjaKoMNR7d2PZFBLQL9wX81jEIPIN
0tsq7/OSj/bZF1p9gkQ9YN+wzvS+1pLlPo1T/GNGrt6ay+ml4mOjezACfrQ+EBB+
ay5XrDbwemAW/tqLMkJMrx28dt8fkNlXv+uzPKpQI5cubBcDyoD/E53rqyybjt+D
pqA9bZ3OORqWHPBZy50eaTs/tyVgBpfXsgcTfbwSedSNnLXxdB0p2pKgPjeAYlCm
DGzxIRSSZjHSBieDm6ZUv/tcplXqrzQxZT/0rhneoG5FK+0g5sayEPQKozdVdFM3
B4a2jzcDbhkNEZ2HV2VVmRp2HHaFRFftuPeoECQGjckoxTo5u9K6cnOymDbf2lN0
/0Jec1LUDWLYUtzNonBpPdlUIxlllT6Q0Q==
=ANji
-----END PGP MESSAGE-----
EOM
GPGMeh.decrypt(encrypted_message) do |key_id|
  # This is the passphrase callback. The argument is Spiff's secret sub key id
  # that Rick used to encypt the message.
  # Return value: the secret keyring passphrase
  "spiff's-secret-keyring-passphrase"
end
```

### Symmetric Encryption: Rick wants to symmetrically encrypt and sign a message

```ruby
GPGMeh.encrypt_symmetric("boom") do |key_id|
  # This is the passphrase callback. The argument is Rick's secret key id OR :symmetric
  if key_id == :symmetric
    "the-symmetric-passphrase"
  else
    "rick's-secret-keyring-passphrase"
  end
end
```

### Override default configuration

```ruby
# 7CAAAB91 is Spaceman Spiff's public key id; multiple recipients can be specified
GPGMeh.encrypt(
  "boom",
  ["7CAAAB91"],
  gpg_options: {
    cmd: "/usr/local/bin/gpg",
    homedir: "/tmp/.gnupg",
    timeout_sec: 10
  }
) do |key_id|
  # This is the passphrase callback. The argument is Rick's secret key id.
  # Return value: the secret keyring passphrase
  "rick's-secret-keyring-passphrase"
end
```

## GPG documentation

The gpg 1.4
[docs](https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=doc/DETAILS;hb=refs/heads/STABLE-BRANCH-1-4)
describe the key types and status-fd output format.

## GPG setup (this was done to setup the tests, here for posterity)

Generate key for Rick Hardslab

```
gpg --homedir spec/support/rickhardslab --gen-key
```

Generate key for Spaceman Spiff

```
gpg --homedir spec/support/spacemanspiff --gen-key
```

Rick Hardslab imports Spaceman Spiff's public key

```
gpg --homedir spec/support/rickhardslab --import spacemanspiff/pubring.gpg
```

Rick Hardslab trusts Spaceman Spiff's public key

```
gpg --homedir spec/support/spacemanspiff --export-ownertrust | gpg --homedir spec/support/rickhardslab --import-ownertrust
```

Spaceman Spiff imports Rick Hardslab's public key

```
gpg --homedir spec/support/spacemanspiff --import rickhardslab/pubring.gpg
```

Spaceman Spiff trusts Rick Hardslab's public key

```
gpg --homedir spec/support/rickhardslab --export-ownertrust | gpg --homedir spec/support/spacemanspiff --import-ownertrust
```

Edit Rick's Key so a "uid" record exists for the tests to ignore ;)

```
gpg --homedir spec/support/rickhardslab/ --edit-key 7A9910E0243D6FEB
# Edit the fields and "save" to exit
```

Rick Hardslab's keys

```
% gpg --homedir spec/support/rickhardslab/ -k
rickhardslab/pubring.gpg
------------------------
pub   2048R/243D6FEB 2016-01-18
uid                  Richard Hardslab (The Real Rick) <richard@example.com>
uid                  Rick Hardslab <rick@example.com>
sub   2048R/7FCAE6B3 2016-01-18

pub   2048R/7CAAAB91 2016-01-18
uid                  Spaceman Spiff <spiff@example.com>
sub   2048R/11AB415A 2016-01-18

% gpg --homedir spec/support/rickhardslab -K
rickhardslab/secring.gpg
------------------------
sec   2048R/243D6FEB 2016-01-18
uid                  Rick Hardslab <rick@example.com>
uid                  Richard Hardslab (The Real Rick) <richard@example.com>
ssb   2048R/7FCAE6B3 2016-01-18
```

Spaceman Spiff's keys

```
% gpg --homedir spec/support/spacemanspiff -K
spacemanspiff/secring.gpg
-------------------------
sec   2048R/7CAAAB91 2016-01-18
uid                  Spaceman Spiff <spiff@example.com>
ssb   2048R/11AB415A 2016-01-18

% gpg --homedir spec/support/spacemanspiff -k
spacemanspiff/pubring.gpg
-------------------------
pub   2048R/7CAAAB91 2016-01-18
uid                  Spaceman Spiff <spiff@example.com>
sub   2048R/11AB415A 2016-01-18
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run
`bundle exec rake` to run the tests. You can also run `bin/console` for an
interactive prompt that will allow you to experiment. If lots of tests fail,
check you are using the correct version of gpg. You can specify the `gpg`
binary with: `GPG=gpg1 bundle exec rake`.

To install this gem onto your local machine, run `bundle exec rake install`. To
release a new version, update the version number in `version.rb`, and then run
`bundle exec rake release`, which will create a git tag for the version, push
git commits and tags, and push the `.gem` file to
[rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/square/gpgmeh.

If you would like to contribute code to GPGMeh, thank you! You can do so
through GitHub by forking the repository and sending a pull request. However,
before your code can be accepted into the project we need you to sign Square's
(super simple) [Individual Contributor License Agreement
(CLA)](https://spreadsheets.google.com/spreadsheet/viewform?formkey=dDViT2xzUHAwRkI3X3k5Z0lQM091OGc6MQ&ndplr=1)

## License

    Copyright 2016 Square, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
