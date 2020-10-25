# wikk_password

* Docs :: https://wikarekare.github.io/wikk_password/
* Source :: https://github.com/wikarekare/wikk_password
* Gem :: https://rubygems.org/gems/wikk_password

## DESCRIPTION:

Reads/writes password file entries of format user:password and provides tests for password validity.
Works with standard unix password types, clear text for testing, and decryptable AES_256_CBC.

## FEATURES/PROBLEMS:

*Should have locking around the changes to the password file, but haven't gotten around to the Lockfile gem yet.

## SYNOPSIS:

conf = WIKK::Configuration.new('test.js')
```
require 'wikk_password'
require 'wikk_configuration

rachel = WIKK::Password.new('rachel', conf)
```
###Sample password file entry
```
rob:$aes256$cxpzz9BMCOvyqfyngashHA==$Z9qOyqgMa4V7ffnI0NOjIhPv+ObAfhC0vyNPXoR5bbw=
```
###Sample Configuration file (or equivalent Ruby hash or any class with attr_reader :passwordFile, :encryption, :key )
```
{
  "passwordFile": "passwd",
  "encryption": "aes256", //"none"
  "key": "kzyE95G6OTkvteywPkhvP0Y9RhM8tZxQMnCOTH7LXrA="
}
```

## REQUIREMENTS:

###Gem requires
* require 'unix_crypt'
* require 'wikk_aes_256'

## INSTALL:

* sudo gem install unix_crypt wikk_aes_256 wikk_password

## LICENSE:

(The MIT License)

Conversion of original wikarekare library to gem

Copyright (c) 2004-2016

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
