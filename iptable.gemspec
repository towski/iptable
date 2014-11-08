Gem::Specification.new do |s|
  s.name        = 'iptable'
  s.version     = '0.0.2'
  s.date        = '2014-11-05'
  s.summary     = "IP Table"
  s.description = "manipulate iptables"
  s.authors     = ["towski"]
  s.email       = 'towski@gmail.com'
  s.homepage    = 'http://rubygems.org/gems/iptable'
  s.license     = 'MIT'
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  #s.add_dependency('rails', '>= 3.0.7')
  #s.add_dependency('render_anywhere')
end
