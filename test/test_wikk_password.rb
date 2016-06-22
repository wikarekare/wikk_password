require "test/unit"
require "wikk_password"
require "wikk_aes_256"
require "wikk_configuration"
require "openssl"
require 'digest/sha2'
require 'base64'

require 'pp'
puts "************  Create initial password file (passwd)  ************"
File.open('passwd', 'w+') do |fd|
  fd.puts <<-EOF
rob:$aes256$cxpzz9BMCOvyqfyngashHA==$Z9qOyqgMa4V7ffnI0NOjIhPv+ObAfhC0vyNPXoR5bbw=
paul:$aes256$cxpzz9BMCOvyqfyngashHA==$9fvi6HvsXzc1jmkoIrKf0Q==
arthur:$ct$$ClearTextPasswd
a:$1$B7MDLZw4$aXO.KuKFYLVzF3Reoj.gt/
b:$6$T/IaPjzt$KvPd51kOsZuBxzJkm81DtaTqiqTQ64ZmgdQwElfjMh0pZu0awPKA9E29KvPYS6.fITYtt1WSJ6aGIt2vzoxHB/
EOF
end

puts "************  Create test config file (test.js)  ************"
File.open('test.js', 'w+') do |fd|
  fd.puts <<-EOF
{
  "passwordFile": "passwd",
  "encryption": "aes256", //"none"
  "key": "kzyE95G6OTkvteywPkhvP0Y9RhM8tZxQMnCOTH7LXrA="
}
EOF
end

conf = WIKK::Configuration.new('test.js')

puts "************  Get user record for rob  ************"
rob = WIKK::Password.new('rob', conf)
puts "Username           #{rob.user}"
puts "File password      #{rob.password}"

puts "************  Validate password for rob  ************"
test_password = "bewaretheidesofmarch"
puts "test_password (#{test_password}) is valid? #{rob.valid?(test_password)}"

puts "************  Adding user astra  ************"
astra_pwd = 'givemefliberty'
begin
  WIKK::Password.add_user('astra', astra_pwd, conf)
rescue IndexError => error
  puts error
end
puts "************  Check user astra exists ************"
p2 = WIKK::Password.new('astra', conf)
puts "Username           #{p2.user}"
puts "File password      #{p2.password}"
puts "Astra's password is valid? #{p2.valid?(astra_pwd)}"

puts "************  Adding user paul, who already exists in password file  ************"
begin
  WIKK::Password.add_user('paul','orgivemecash', conf)
rescue IndexError => error
  puts error
end
puts "************  Adding user ben, with no password  ************"
begin
  WIKK::Password.add_user('ben','', conf)
rescue Exception => error
  puts error
end

puts "************ Test passwd + hash ****************"
challenge = WIKK::AES_256.gen_key_to_s
puts "Test password = #{test_password}   Challenge => #{challenge}"
test_digest = Digest::SHA256.digest(test_password + challenge).unpack('H*')[0]
puts "test digest response       #{test_digest}"
puts "check digest for user rob  #{rob.valid_sha256_response?(challenge, test_digest)}"

puts "************ Test with hashed version of config file. *********************"
puts "************  Create a user rachel, with no password  ************"
rachel = WIKK::Password.new('rachel', {:encryption => "aes256", :passwordFile => "passwd", :key => "kzyE95G6OTkvteywPkhvP0Y9RhM8tZxQMnCOTH7LXrA="}, true)
puts "Initial password => '#{rachel.password}'"
puts "************  Set rachel's  password to #{test_password} ************"
rachel.set_password(test_password)
puts "is password valid? #{rachel.valid?(test_password)}"
puts "************  Save rachel's entry to password file ************"
rachel.save

puts "************  Get user record for arthur and check password  ************"
arthur = WIKK::Password.new('arthur', conf)
puts "Arthur's password is valid? #{arthur.valid?('ClearTextPasswd')}"



