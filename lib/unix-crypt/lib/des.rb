module UnixCrypt
  class DES < UnixCrypt::Base
    def self.hash(*_args)
      raise 'Unimplemented for DES'
    end

    def self.construct_password(password, salt, _rounds)
      password.crypt(salt)
    end

    def self.default_salt_length
      2
    end

    def self.max_salt_length
      2
    end
  end
end
