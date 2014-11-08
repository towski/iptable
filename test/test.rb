gem 'mocha'
require 'minitest/autorun'
require 'iptable'
require 'mocha/mini_test'
require 'socket'

class Tests < Minitest::Test
  def test_rule_matching
    chain = IP::Chain.new :name => "hey"
    str = "607939 956613034 TRAFFIC_ACCT_OUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0          "
    chain.match_rule str
    assert chain.rules.size == 1
  end

  def test_match_chain
    IP::Table.any_instance.expects(:load_chains)
    table = IP::Table.new
    assert table.match_chain "Chain OUTPUT (policy ACCEPT 607201 packets, 960137939 bytes) "
  end

  def test_match_chain_without_policy
    IP::Table.any_instance.expects(:load_chains)
    table = IP::Table.new
    assert table.match_chain "Chain TRAFFIC_ACCT (0 references)"
  end

  def test_add_chain_tcp
    table = IP::Table.new
    chain = table.add_chain :name => "nginx_in"
    table.chains["INPUT"].append_jump_to chain
    rule = chain.add_rule :protocol => :tcp, :dport => 1999
    server_thread = Thread.new do
      server = TCPServer.new 1999
      server.accept
      sleep 0.1
    end
    client_thread = Thread.new do
      client = TCPSocket.new 'localhost', 1999
      sleep 0.1
      client.puts "hey"
    end
    client_thread.join
    server_thread.join
    chain.reload
    assert_equal 4, chain.rules.first.packets
    ensure
    chain.delete
  end

  def test_add_chain_udp
    table = IP::Table.new
    chain = table.add_chain :name => "nginx_in"
    table.chains["INPUT"].append_jump_to chain
    rule = chain.add_rule :protocol => :udp, :dport => 1998
    server_thread = Thread.new do
      server = UDPSocket.new
      server.bind "localhost", 1998
      text, sender = server.recvfrom(1)
    end
    client_thread = Thread.new do
      client = UDPSocket.new
      client.send("hello", 0, 'localhost', 1998)
    end
    client_thread.join
    server_thread.join
    chain.reload
    assert_equal 1, chain.rules.first.packets
    ensure
    chain.delete
  end
end
