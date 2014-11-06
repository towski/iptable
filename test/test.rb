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

  def test_add_chain
    table = IP::Table.new
    chain = table.add_chain :name => "nginx_in"
    rule = chain.add_rule :protocol => :tcp, :dport => 2000
    server_thread = Thread.new do
      server = TCPServer.new 2000
      server.accept
      puts "accept"
    end
    client_thread = Thread.new do
      client = TCPSocket.new 'localhost', 2000
      client.puts "hey"
    end
    client_thread.join
    server_thread.join
    chain.reload
    assert_equal 0, chain.rules.first.packets
    ensure
    chain.delete
  end
end
