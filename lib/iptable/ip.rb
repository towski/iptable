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

    def add_chain(options)
      new_chain = Chain.new(options)
      new_chain.save
      @chains[options[:name]] = new_chain
    end

    def match_chain(line)
      if match = line.match(CHAIN_RE)
        name = match[1]
        @current_chain = @chains[name] = Chain.new(:name => name)
        return true
      end
      false
    end
  end

  class Chain
    attr_reader :rules, :name
    attr_accessor :reference

    def initialize(options)
      @name = options[:name]
      @rules = []
      @reference = nil
    end

    def save
      IO.popen("/sbin/iptables -N #{@name}") do |output|
        if output.read =~ /Chain already exists/
          return false
        else
          return true
        end
      end
    end

    def append_jump_to chain
      chain.reference = self
      IO.popen("/sbin/iptables -I #{@name} -j #{chain.name}") do |output|
        puts output.read
      end
    end

    def init_rule(options)
      @rules << Rule.new(options.merge(:chain => self))
    end

    def add_rule(options)
      new_rule = Rule.new(options.merge(:chain => self))
      new_rule.save
      @rules << new_rule
    end

    def match_rule(string)
      if match = string.match(RULE_RE)
        init_rule :packets => match[1], :protocol => match[2]
      end
    end

    def delete
      @rules.each do |rule|
        IO.popen("/sbin/iptables -D #{@name} 1") do |output|
          puts output.read
        end
      end
      if @reference
        IO.popen("/sbin/iptables -D #{@reference.name} -j #{@name}") do |output|
          puts output.read
        end
      end
      IO.popen("/sbin/iptables -X #{@name}") do |output|
        puts output.read
      end
    end

    def reload
      @rules = []
      IO.popen("/sbin/iptables -L #{@name} -n -v -x") do |output|
        output.readlines.each do |line|
          match_rule(line)
        end
      end
    end
  end

  class Rule
    attr_accessor :chain, :target
    attr_reader :packets

    def initialize(options)
      @chain = options[:chain]
      raise "Rule needs a chain" unless @chain
      @packets = options[:packets].to_i
      @target = nil
    end

    def save
      IO.popen("/sbin/iptables -A #{@chain.name} -p tcp --dport 2000") do |output|
        puts output.read
      end
    end
  end
end
