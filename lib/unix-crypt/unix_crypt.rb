# Copyright (c) 2013, Roger Nesbitt
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# Neither the name of the unix-crypt nor the names of its contributors may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED # WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'digest'
require 'securerandom'

module UnixCrypt
  VERSION = '1.3.0'

  Error = Class.new(StandardError)
  SaltTooLongError = Class.new(Error)

  def self.valid?(password, string)
    # Handle the original DES-based crypt(3)
    return password.crypt(string) == string if string.length == 13

    # All other types of password follow a standard format
    return false unless (m = string.match(/\A\$([156])\$(?:rounds=(\d+)\$)?(.+)\$(.+)/))

    hash = IDENTIFIER_MAPPINGS[m[1]].hash(password, m[3], m[2] && m[2].to_i)
    hash == m[4]
  end
end

require_relative 'lib/base'
require_relative 'lib/des'
require_relative 'lib/md5'
require_relative 'lib/sha'

UnixCrypt::IDENTIFIER_MAPPINGS = {
  '1' => UnixCrypt::MD5,
  '5' => UnixCrypt::SHA256,
  '6' => UnixCrypt::SHA512
}
