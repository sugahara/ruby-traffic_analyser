require 'pcap'

class CapData
  attr_accessor :queue, :cap, :cap_dev, :prev_flow_size, :start_time, :window_time

  def initialize(protocols, cap_dev, start_time, window_time)
    @window_time = window_time
    @queue = Hash.new
    protocols.each do |p|
      @queue[p] = Hash.new
    end

    @cap = Pcap::Capture.open_live(cap_dev)
    @cap_dev = cap_dev
    @start_time = start_time
    @prev_flow_size = Hash.new(0)
  end
  
  

end
