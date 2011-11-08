class AnomalyLogger

  def initialize(logname, margin, threshold)
    @logname = logname
    @margin = margin
    @threshold = threshold
    @date = Time.now.strftime("%Y%m%d")
  end

  def check(value)
    @threshold.each do |th|
      if value >= (th - @margin) && value <= (th + @margin)
        @state = value 
        return true
      end
    end
    return false
  end

  def logging(dump)
    if @date != Time.now.strftime("%Y%m%d")
      @date = Time.now.strftime("%Y%m%d")
    end
    File.open("dump_log/#{@logname}.log.#{@date}", 'a') do |f|
      f.puts Time.now.strftime("%Y/%m/%d-%H:%M:%S")
      f.puts "state: #{@state}"
      dump.each do |pkt|
        f.puts "#{pkt.src}:#{pkt.sport} => #{pkt.dst}:#{pkt.dport}"
        f.puts "#{pkt.tcp_data}" if pkt.tcp?
        f.puts "#{pkt.udp_data}" if pkt.udp?
        f.puts ""
      end
      f.puts ""
    end
  end

end
