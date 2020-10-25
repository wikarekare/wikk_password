module WIKK 
  require 'wikk_aes_256'
  require 'digest/sha2'
  require 'unix_crypt'
  require 'base64'
  
  # READS/WRITES our private password file entries.
  #
  # @attr_reader [String] user the decrypted text
  # @attr_reader [String] password the encrypted password, in form $type$initial_vector$encrypted_text
  class Password
    VERSION = '0.1.2'

    attr_reader :user, :password
    
    # New. Fetches a user entry from the password file, or creates a new user (call via Passwd::add_user)
    #
    # @param user [String] User name to fetch from password file, or to create, if new_user == true
    # @param config [WIKK:Configuration] or hash or class with attr_readers :passwordFile, :encryption, :key
    # @param new_user [Boolean] If true, then the user shouldn't be in password file.
    # @return [WIKK::Password]
    # @raise [IndexError] if the user entry exists.
  	def initialize(user, config, new_user=false)
      if config.class == Hash
        sym = config.each_with_object({}) { |(k,v),h| h[k.to_sym] = v }
        @config = Struct.new(*(k = sym.keys)).new(*sym.values_at(*k))
      else
    	  @config = config
      end
  	  raise IndexError, "User \"#{user}\" not found" if getpwnam(user) == false && !new_user
  	end
  	
  	# Sets the user password, but does not save this. You must call save().
    #
  	# @param password [String] the clear text password to encypt
  	# @return [String] the password file password entry.
    def set_password(password) 
      @password = encrypt(password, @config.encryption)
    end
    
    # Compare an SHA256 hashed password + challenge with this users password
    #
    # @param challenge [String] a random string, sent to the remote client, added to the password, and SHA256 hashed
    # @param response [String] the remote clients hex_SHA256(password + challenge)
    # @return [Boolean] True if the users password matches the one that created the response.
    # @note The password entry must be decryptable, not a UNIX style hash.
    # @raise [ArgumentError] if the encryption method is unknown.
    def valid_sha256_response?(challenge, response)
      return response == Digest::SHA256.digest(decrypt + challenge).unpack('H*')[0]
    end
    
    # Compare an SHA256 hashed password + challenge with this users password
    #
    # @param user [String] User name to fetch from password file, or to create, if new_user == true
    # @param config [WIKK:Configuration] or hash or class with attr_readers :passwordFile, :encryption, :key
    # @param challenge [String] a random string, sent to the remote client, added to the password, and SHA256 hashed
    # @param response [String] the remote clients hex_SHA256(password + challenge)
    # @return [Boolean] True if the users password matches the one that created the response.
    # @note The password entry must be decryptable, not a UNIX style hash.
    # @raise [ArgumentError] if the encryption method is unknown.
    def self.valid_sha256_response?(user, config, challenge, response)
      self.new(user, config).valid_sha256_response?(challenge, response)
    end
      
    # Compares the password with the user's password by encrypting the password passed in
    #
    # @param password [String] The clear text password
    # @return [Boolean] True if the passwords match
    # @raise [ArgumentError] if the encryption method is unknown.
    def valid?(ct_password)
      ignore,encryption,iv,password = @password.split('$')
      encryption = 'DES' if ignore != '' #No $'s in DES password, so ignore has text.
      case encryption
      when 'ct'; return ct_password == @password
      when 'aes256'; return encrypt(ct_password, encryption, iv) == @password
      when 'DES'; return UnixCrypt.valid?(ct_password, @password) 
      when 'MD5','1','SHA256','5','SHA512','6'; return UnixCrypt.valid?(ct_password, @password)
      else raise ArgumentError, "Unsupported encryption algorithm $#{encryption}"
      end
    end
    
    # Adds a user to the password file
    #
    # @param user [String] New user name. Raises an error if the user exists
    # @param password [String] Clear text password. Raises an error if this is nil or ''
    # @note Modifies the password file.
    # @raise [IndexError] if the user entry exists.
    # @raise [ArgumentError] if the password is nil or empty.
    def self.add_user(user,password,config)
      user_record = self.new(user, config, true)
      raise IndexError, "User \"#{user}\" is already present"  if user_record.password != nil
      raise ArgumentError, "Password can't be empty" if password == nil || password == ''
      user_record.set_password(password)
      user_record.save
    end
        
    # Saves changes or a new user entry into the password file
    #
    def save
      loadfile
      @pwent[@user] = @password
      writefile
    end
    
    # Outputs password file entry as a string
    #
    # @return [String] password file entry.
    def to_s
      "#{@user}:#{@password}"
    end

  	private
  	
  	# Fetch a password file entry by user's name
    #
  	# @param user [String] user name
  	# @return [Boolean] True if user entry exists
  	def getpwnam(user)
  	  loadfile
  	  @user = user
  	  @password = @pwent[@user]
  	  return @password != nil #i.e. Found a user entry
	  end
	  
	  # Read the password file into the @pwent hash
    #
  	def loadfile
  	  @pwent = {}
  	  File.open(@config.passwordFile, "r") do |fd|
  	    fd.each do |line|
  	      tokens = line.chomp.split(/:/)
  	      @pwent[tokens[0]] = tokens[1] if tokens[0] != ''
	      end
      end
    end
    
	  # Overwrite the password file from the @pwent hash
    #
  	def writefile
  	  File.open(@config.passwordFile, "w+") do |fd|
  	    @pwent.each do |k,v|
  	      fd.puts "#{k}:#{v}"
	      end
      end
    end
    
  	# Encrypts a clear text password
    #
  	# @param password [String] The clear text password
  	# @param challenge [String] Norm
    # @raise [ArgumentError] if the encryption algorithm isn't known.
    def encrypt(password,  algorithm = "aes256", pwd_iv = nil)
      case algorithm
      when "aes256"
        password,key,iv = WIKK::AES_256.cipher_to_s(password, @config.key, pwd_iv)
        return "$aes256$#{iv}$#{password}"
      when "DES"
        return UnixCrypt::DES.build(password)
      when "MD5","1" #Unix passward digest, which is multiple hashes
        return UnixCrypt::MD5.build(password)
      when "SHA256","5" #Unix passward digest, which is multiple hashes
        return UnixCrypt::SHA256.build(password)
      when "SHA512","6" #Unix passward digest, which is multiple hashes
        return UnixCrypt::SHA512.build(password)
      when 'ct' #ct == clear text
        return "$ct$$#{password}"
      else
        raise ArgumentError, "Unsupported Encryption algorithm #{@config.encryption}"
      end
    end
    
    # Decrypts @password, if this is possible
    #
    # @return [String] the clear text password
    # @raise [ArgumentError] if the encryption type can't be decrypted.
    def decrypt
      ignore,encryption,iv,password = @password.split('$')
      case encryption
      when 'ct' ; password
      when 'aes256'
        ct_password, ct_key, ct_iv = WIKK::AES_256.decrypt(password, true, @config.key, iv)
        return ct_password
      else
        raise ArgumentError, "Unsupported decryption algorithm #{@config.encryption}"
      end
    end
  end
end





