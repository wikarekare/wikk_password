#!/usr/local/bin/ruby
require 'test/unit'
require_relative '../lib/wikk_password.rb'
require 'wikk_configuration'
require 'openssl'
require 'digest/sha2'
require 'base64'

require 'pp'
puts '************  Create initial password file (passwd)  ************'
File.open(__dir__ + '/passwd', 'w+') do |fd|
  fd.puts <<~EOF
    rob:$aes256$cxpzz9BMCOvyqfyngashHA==$Z9qOyqgMa4V7ffnI0NOjIhPv+ObAfhC0vyNPXoR5bbw=
    paul:$aes256$cxpzz9BMCOvyqfyngashHA==$9fvi6HvsXzc1jmkoIrKf0Q==
    arthur:$ct$$ClearTextPasswd
    des:iv2znaS/6eSJw
    md5:$1$erj3mvc3$/N8..cKHAdKuiDPa1Ju5F1
    sha256:$5$VHp3Nc4siV2ujQYz$.0sy2MuMtM9KRHxcqUKfvEaqFnDhFtZskPBotvuE1FA
    sha512:$6$2.wis0LWdIA6672L$el2WeN3rk4c9gTEZOt1miLgAVLHIOURNQESma2cUm/OCWQYvxKIo3fqSlKfr.H1MufURRrFLn5OTh52JnZ.He.
  EOF
end

puts '************  Create test config file (test.js)  ************'
File.open(__dir__ + '/test.js', 'w+') do |fd|
  fd.puts <<~EOF
    {
      "passwordFile": "passwd",
      "encryption": "aes256", //"none"
      "key": "kzyE95G6OTkvteywPkhvP0Y9RhM8tZxQMnCOTH7LXrA="
    }
  EOF
end

conf = WIKK::Configuration.new('test.js')

puts '************  Get user record for rob  ************'
rob = WIKK::Password.new('rob', conf)
puts "Username           #{rob.user}"
puts "File password      #{rob.password}"

puts '************  Validate password for rob  ************'
test_password = 'bewaretheidesofmarch'
puts "test_password (#{test_password}) is valid? #{rob.valid?(test_password)}"

puts '************  Adding user astra  ************'
astra_pwd = 'givemefliberty'
begin
  WIKK::Password.add_user('astra', astra_pwd, conf)
rescue IndexError => e
  puts e
end
puts '************  Check user astra exists ************'
p2 = WIKK::Password.new('astra', conf)
puts "Username           #{p2.user}"
puts "File password      #{p2.password}"
puts "Astra's password is valid? #{p2.valid?(astra_pwd)}"

puts '************  Adding user paul, who already exists in password file  ************'
begin
  WIKK::Password.add_user('paul', 'orgivemecash', conf)
rescue IndexError => e
  puts e
end
puts '************  Adding user ben, with no password  ************'
begin
  WIKK::Password.add_user('ben', '', conf)
rescue StandardError => e
  puts e
end

puts '************ Test passwd + hash ****************'
challenge = WIKK::AES_256.gen_key_to_s
puts "Test password = #{test_password}   Challenge => #{challenge}"
test_digest = Digest::SHA256.digest(test_password + challenge).unpack1('H*')
puts "test digest response       #{test_digest}"
puts "check digest for user rob  #{rob.valid_sha256_response?(challenge, test_digest)}"
puts "check digest for user rob  #{WIKK::Password.valid_sha256_response?('rob', conf, challenge, test_digest)}"

puts '************ Test with hashed version of config file. *********************'
puts '************  Create a user rachel, with no password  ************'
rachel = WIKK::Password.new('rachel', { encryption: 'aes256', passwordFile: 'passwd', key: 'kzyE95G6OTkvteywPkhvP0Y9RhM8tZxQMnCOTH7LXrA=' }, true)
puts "Initial password => '#{rachel.password}'"
puts "************  Set rachel's  password to #{test_password} ************"
rachel.set_password(test_password)
puts "is password valid? #{rachel.valid?(test_password)}"
puts "************  Save rachel's entry to password file ************"
rachel.save

puts '************  Get user record for arthur and check password  ************'
arthur = WIKK::Password.new('arthur', conf)
puts "Arthur's password is valid? #{arthur.valid?('ClearTextPasswd')}"

puts '************  set user password for user des using DES  ************'
conf.encryption = 'DES'
des = WIKK::Password.new('des', conf)
puts "Username           #{des.user}"
des.set_password(test_password)
des.save
puts "is password valid? #{des.valid?(test_password)}"

puts '************  set user password for user md5 MD5   ************'
conf.encryption = 'MD5'
md5 = WIKK::Password.new('md5', conf)
puts "Username           #{md5.user}"
md5.set_password(test_password)
md5.save
puts "is password valid? #{md5.valid?(test_password)}"

puts '************  set user password for user sha256 using SHA256  ************'
conf.encryption = 'SHA256'
sha256 = WIKK::Password.new('sha256', conf)
puts "Username           #{sha256.user}"
sha256.set_password(test_password)
sha256.save
puts "is password valid? #{sha256.valid?(test_password)}"

puts '************  set user password for user sha512 using SHA512  ************'
conf.encryption = 'SHA512'
sha512 = WIKK::Password.new('sha512', conf)
puts "Username           #{sha512.user}"
sha512.set_password(test_password)
sha512.save
puts "is password valid? #{sha512.valid?(test_password)}"
