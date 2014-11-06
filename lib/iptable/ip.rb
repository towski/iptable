module IP
  CHAIN_RE = /Chain ([a-zA-Z_]+) (\(policy ACCEPT ([0-9]+) packets, ([0-9]+) bytes\)){0,1}/
  RULE_RE = /([0-9]+)\s+([0-9]+)\s+([a-zA-Z_]*)\s+([a-z]*)\s+--\s+\*\s+\*\s+([0-9\.\/]+)\s+([0-9\.\/]+)\s*(tcp (dpt|spt):([0-9]+)){0,1}/

  class Table
    attr_reader :chains

    def initialize(load_iptables = true)
      @chains = {}
      load_chains if load_iptables
    end

    def refresh
      @chains = {}
      load_chains
    end

    def load_chains
      IO.popen("/sbin/iptables -L -n -v -x") do |output|
        output.readlines.each do |line|
          next if match_chain(line)
          @current_chain.match_rule(line) if @current_chain
        end
      end
    end

    def match_chain(line)
      if match = line.match(CHAIN_RE)
        name = match[1]
        @current_chain = @chains[name] = Chain.new(name)
        return true
      end
      false
    end
  end

  class Chain
    attr_reader :rules

    def initialize(name)
      @name = name
      @rules = []
    end

    def add_rule(*args)
      @rules << Rule.new(args)
    end

    def match_rule(string)
      if match = string.match(RULE_RE)
        add_rule match[1, -1]
      end
    end
  end

  class Rule
    attr_accessor :chain, :target

    def initialize(*args)
      @chain = nil
      @target = nil
    end
  end
end
