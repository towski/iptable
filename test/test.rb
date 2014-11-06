gem 'mocha'
require 'minitest/autorun'
require 'iptable'
require 'mocha/mini_test'

class Tests < Minitest::Test
  def test_rule_matching
    chain = IP::Chain.new "hey"
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
end
