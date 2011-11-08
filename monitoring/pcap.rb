# -*- coding: utf-8 -*-
require 'rubygems'
require 'pcap'
require 'socket'

#require 'daemons'

#include Daemonize

#daemonize(STDOUT)


sock = UDPSocket.new

#dev = Pcap.lookupdev
if ARGV[0] then
  dev = ARGV[0]
else
  dev = "en2"
end
cap = Pcap::Capture.open_live(ARGV[0])
#cap.setfilter(ARGV[0]) #setfilterはすごく重い・・・

cap.loop do |pkt|
  sock.send(Marshal.dump(pkt), 0, "127.0.0.1", 8083)
  #print pkt, "\n"
  #print pkt.raw_data, "\n"
end
cap.close
sock.close
