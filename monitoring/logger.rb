# -*- coding: utf-8 -*-
require 'pcap'
require './anomaly-logger.rb'
require 'mysql'
include DataHandler

class Logger
  def initialize(data)
    @data = data
    @dumper = Hash.new
    @anomaly_logger = Hash.new
    @anomaly_logger_args = Array.new
    # @db = Mysql::new("127.0.0.1","ruby","suga","ruby")
    @table_name = @data.start_time.strftime("%Y%m%d-%H%M%S")
  end

  def create_new() # create new log file and table
    @data.queue.each do |protocol, v|
      File.open("log/flow/#{protocol}_flow.log.#{@data.start_time.strftime("%Y%m%d-%H%M%S")}", 'a') do |f|
        f.puts @data.start_time.strftime("%Y/%m/%d-%H:%M:%S")
      end

      File.open("log/#{protocol}_packet.log.#{@data.start_time.strftime("%Y%m%d-%H%M%S")}", 'a') do |f|
        f.puts @data.start_time.strftime("%Y/%m/%d-%H:%M:%S")
      end

    end
  end

  # AnomalyLogger must be declared for each protocol
  def create_new_anomaly_logger(protocol, range, mu)
    @anomaly_logger_args = [protocol, range, mu]
    @dumper[protocol] = Pcap::Dumper.open(@data.cap, "dump_log/#{protocol}_anomaly.#{@data.start_time.strftime("%Y%m%d-%H%M%S")}.pcap")

    @table_name = @data.start_time.strftime("%Y%m%d-%H%M%S")
    @anomaly_logger[protocol] = AnomalyLogger.new(protocol, range, mu)
    sql = "CREATE TABLE `ruby`.`#{@table_name}` (`number` INT NOT NULL DEFAULT NULL AUTO_INCREMENT PRIMARY KEY ,`time` DATETIME NOT NULL ,`l4_protocol` TEXT DEFAULT NULL ,`protocol` TEXT DEFAULT NULL ,`source_ip` INT UNSIGNED NOT NULL ,`destination_ip` INT UNSIGNED NOT NULL ,`source_port` INT NOT NULL ,`destination_port` INT NOT NULL ,`length` INT NOT NULL ,`data` LONGBLOB) ENGINE = MYISAM ;"
    # @db.query(sql)
  end

  def out #output line
    # check new date
    if Time.now.day != @data.start_time.day
      @data.start_time = Time.now
      create_new()
      if @anomaly_logger_args[0] != nil
        create_new_anomaly_logger(@anomaly_logger_args[0], @anomaly_logger_args[1], @anomaly_logger_args[2])
      end
    end

    if @flow_count != nil
      @data.queue.each do |protocol, v|
        set_prev_flow_size(@data, protocol, @flow_count[protocol])
      end
    end

    # get value and output
    @packet_count = get_packet_count(@data)
    @flow_count = get_flow_count(@data)

    @data.queue.each do |protocol, v|
      File.open("log/flow/#{protocol}_flow.log.#{@data.start_time.strftime("%Y%m%d-%H%M%S")}", 'a') do |f|
        f.puts @flow_count[protocol]
      end
      File.open("log/#{protocol}_packet.log.#{@data.start_time.strftime("%Y%m%d-%H%M%S")}", 'a') do |f|
        f.puts @packet_count[protocol]
      end
      puts "#{protocol}: flowsize->#{@flow_count[protocol]} packetsize->#{@packet_count[protocol]}"
    end
    puts ""

  end

  def dump
    output_array = Array.new
    @anomaly_logger.each do |protocol, a_logger|
      if a_logger.check(@flow_count[protocol] - @data.prev_flow_size[protocol]) == true
        File.open("dump_log/#{protocol}_anomaly_not_select_filter.#{@data.start_time.strftime("%Y%m%d-%H%M%S")}.txt", 'a') do |f|
          puts "packet dumped!"
          @data.queue[protocol].each do |flow, packet|
            packet.each do |pkt|
              output_array.push pkt
              # @dumper[protocol].dump(pkt)
            end
          end
          #sort by timestamp
          sorted_array = sort output_array
          
          sorted_array.each do |pkt|
            @dumper[protocol].dump(pkt)
            insert_mysql(pkt)
          end
          #dump_start_time = sorted_array.first.time.strftime("%Y-%m-%d %H:%M:%S.%6N")
          dump_start_time = sorted_array.first.time.strftime("%b %d, %Y %H:%M:%S.%N")
          #dump_end_time = sorted_array.last.time.strftime("%Y-%m-%d %H:%M:%S.%6N")
          #dump_end_time = sorted_array.last.time.strftime("%b %d, %Y %H:%M:%S.%N")
          dump_end_time = (sorted_array.first.time + 5).strftime("%b %d, %Y %H:%M:%S.%N")
          f.print("!(frame.time >= \"#{dump_start_time}\" and frame.time <= \"#{dump_end_time}\") and ")
        end
      end
    end
  end
  
  def merge ary1, ary2
    new_ary = []
    until (ary1.empty? || ary2.empty?)
      if ary1.first.time < ary2.first.time
        new_ary << ary1.shift
      else
        new_ary << ary2.shift
      end
  end
    new_ary += ary1 + ary2
  end
  
  def sort ary
    return ary if ary.size == 1
    point = ary.size / 2
    ary_a = sort ary[0...point]
    ary_b = sort ary[point..-1]
    merge ary_a, ary_b
  end
  
  def insert_mysql pkt
    if pkt.udp?
      time = pkt.time.strftime("%Y%m%d%H%M%S")
      src_ip = pkt.ip_src.to_i
      dst_ip = pkt.ip_dst.to_i
      src_port = pkt.sport
      dst_port = pkt.dport
      length = pkt.ip_len
      data = pkt.udp_data
    end
    sql = "INSERT INTO `#{@table_name}` (`number` ,`time` ,`source_ip` ,`destination_ip` ,`source_port` ,`destination_port` ,`length`, `data`)VALUES (NULL , '#{time}', '#{src_ip}', '#{dst_ip}', '#{src_port}', '#{dst_port}', '#{length}', NULL)"
    # @db.query(sql)
  end

  
end
