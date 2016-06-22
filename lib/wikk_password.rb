module WIKK 
  require 'wikk_aes_256'
  require 'digest/sha2'
  require 'unix_crypt'
  require 'base64'
  
  #READS/WRITES our private password file entries.
  class Password
    VERSION = '0.1.0'

    attr_reader :user, :password
    
  	def initialize(user, config, new_user=false)
      if config.class == Hash
        sym = config.each_with_object({}) { |(k,v),h| h[k.to_sym] = v }
        @config = Struct.new(*(k = sym.keys)).new(*sym.values_at(*k))
      else
    	  @config = config
      end
  	  raise IndexError, "User \"#{user}\" not found" if getpwnam(user) == false && !new_user
  	end
  	
    def encrypt(password, challenge = '', algorithm = "aes256")
      encrypt_me = password + challenge
      case algorithm
      when "aes256"
        password,key,iv = WIKK::AES_256.cipher_to_s(encrypt_me, @config.key, nil)
        return "$aes256$#{iv}$#{password}"
      when "DES"
        return UnixCrypt::DES.build(encrypt_me)
      when "MD5" #Unix passward digest, which is multiple hashes
        return UnixCrypt::MD5.build(encrypt_me)
      when "SHA256" #Unix passward digest, which is multiple hashes
        return UnixCrypt::SHA256.build(encrypt_me)
      when "SHA512" #Unix passward digest, which is multiple hashes
        return UnixCrypt::SHA512.build(encrypt_me)
      when 'ct' #ct == clear text
        return "$ct$$#{encrypt_me}"
      else
        raise ArgumentError, "Unsupported Encryption algorithm #{@config.encryption}"
      end
    end
    
    def set_password(password) 
      @password = encrypt(password, '', @config.encryption)
    end
    
    def valid_sha256_response?(challenge, response)
      case @config.encryption
      when 'ct'
        return response == Digest::SHA256.digest(@password + challenge).unpack('H*')[0]
      when 'aes256'
        return response == Digest::SHA256.digest(decrypt + challenge).unpack('H*')[0]
      else
        raise ArgumentError, "Unsupported decryption algorithm #{@config.encryption}"
      end        
    end
      
    
    def valid?(password)
      case @config.encryption
      when "DES", "MD5", "SHA256", "SHA512"
        return UnixCrypt.valid?(password, @password)
      when 'ct'
        return password == @password
      when 'aes256'
        return password == decrypt
      else
        raise ArgumentError, "Unsupported decryption algorithm #{@config.encryption}"
      end        
    end
    
    def self.add_user(user,password,config)
      user_record = self.new(user, config, true)
      raise IndexError, "User \"#{user}\" is already present"  if user_record.password != nil
      raise "Password can't be empty" if password == nil || password == ''
      user_record.set_password(password)
      user_record.save
    end
        
    def save
      loadfile
      @pwent[@user] = @password
      writefile
    end
    
    def to_s
      "#{@user}:#{@password}"
    end

  	private
  	def getpwnam(user)
  	  loadfile
  	  @user = user
  	  @password = @pwent[@user]
  	  return @password != nil #i.e. Found a user entry
	  end
	  
  	def loadfile
  	  @pwent = {}
  	  File.open(@config.passwordFile, "r") do |fd|
  	    fd.each do |line|
  	      tokens = line.chomp.split(/:/)
  	      @pwent[tokens[0]] = tokens[1] if tokens[0] != ''
	      end
      end
    end
    
  	def writefile
  	  File.open(@config.passwordFile, "w+") do |fd|
  	    @pwent.each do |k,v|
  	      fd.puts "#{k}:#{v}"
	      end
      end
    end
    
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





