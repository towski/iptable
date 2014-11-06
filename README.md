iptable
=======

Manipulate iptables with ruby, for packet accounting of ports

Must be run as root, typically with rvmsudo

```ruby
require 'iptable'
# load the current iptables
table = IP::Table.new
chain = tables.add_chain :name => "nginx_in"
table.chains["INPUT"].append_jump_to chain
chain.add_rule :protocol => :tcp, :src => "208.51.40.2", :dport => 34576
sleep 5
chain.reload
puts chain.packets
puts chain.bytes
```
