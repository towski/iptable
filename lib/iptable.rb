unless Process.uid == 0
  raise "the iptables gem must be run as root. try 'rvmsudo ruby ...'"
end

require 'iptable/ip'
