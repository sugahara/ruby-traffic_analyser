module DataHandler
  TCP = "tcp"
  UDP = "udp"
  def set_queue(pkt, data)
    if pkt.tcp?
      type = TCP
    elsif pkt.udp?
      type = UDP
    else
      return
    end
    
    flow = {
      "ip_src" => pkt.ip_src,
      "sport" => pkt.sport,
      "ip_dst" => pkt.ip_dst,
      "dport" => pkt.dport
    }
    
    if data.queue[type][flow]
      data.queue[type][flow].push pkt
    else
      data.queue[type][flow] = Array.new
      data.queue[type][flow].push pkt
    end
  end

  def windowing(data)
    data.queue.each do |type, v|
      v.each do |flow, packet|
        while (((packet.last.time.to_f - packet.first.time.to_f) > data.window_time || (Time.now.to_f - packet.first.time.to_f) > data.window_time))
          packet.shift
          break if packet.size == 0
        end
        v.delete(flow) if packet.size == 0
      end
    end
=begin
    data.queue.each do |type, v|
      v.each do |flow, packet|
        packet.each do |pkt|
          if pkt.udp?
            print pkt.time,"\n"
          end
        end
      end
    end
    print "\n"
=end
  end

  def set_prev_flow_size(data, protocol, flow_size)
    data.prev_flow_size[protocol] = flow_size
  end

  def set_prev_packet_size()
    
  end

  def get_flow_count(data)
    flow_count = Hash.new
    data.queue.each do |protocol, v|
      flow_count[protocol] = data.queue[protocol].size
    end
    return flow_count
  end

  def get_packet_count(data)
    packet_count = Hash.new(0)
    data.queue.each do |protocol, v|
      v.each do |flow, packet|
        packet_count[protocol] += packet.size
      end
    end
    return packet_count
  end
  
end
