require 'eventmachine'
require 'pcap'
require './handler.rb'
require './cap-data.rb'
require './logger.rb'
require 'mysql'

include DataHandler

CAPTURE_DEVICE = "en2"
WINDOW_TIME = 5.0

@data = CapData.new(["tcp", "udp"], CAPTURE_DEVICE, Time.now, WINDOW_TIME)
@logger = Logger.new(@data)
@logger.create_new
# AnomalyLogger must be declared for each protocol
# When you need to change argument, you need to change log rotation line in logger.rb
@logger.create_new_anomaly_logger("udp", 5, [21])



module PacketHandler
  #include DataHandler
  attr_writer :data
  @data = nil

  def initialize

  end

  def receive_data(rcv_data)
    pkt = Marshal.load(rcv_data)
    set_queue(pkt, @data)
  end
end

EventMachine::run {
  serv = EM::open_datagram_socket "127.0.0.1", 8083, PacketHandler
  serv.data = @data
  #include DataHandler
  EM::add_periodic_timer(0.1) do
    # windowing
    windowing(@data)
  end

  EM::add_periodic_timer(5) do
    @logger.out
    @logger.dump
  end
}
