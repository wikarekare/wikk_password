# -*- ruby -*-

require 'rubygems'
require 'hoe'
Hoe.plugin :yard

Hoe.spec 'wikk_password' do 
  self.readme_file = "README.md"
  self.developer( "Rob Burrowes","r.burrowes@auckland.ac.nz")
  remote_rdoc_dir = '' # Release to root
  
  self.yard_title = 'wikk_password'
  self.yard_options = ['--markup', 'markdown', '--protected']
  
  self.dependency "unix_crypt", [">= 1.3.0"]
  self.dependency "wikk_aes_256", [">= 0.1.4"]
end


#Validate manfest.txt
#rake check_manifest

#Local checking. Creates pkg/
#rake gem

#create doc/
#rake docs  

#Copy up to rubygem.org
#rake release VERSION=1.0.1
