# -*- coding: utf-8 -*-
require 'rubygems'
require 'pcap'
require 'mysql'
#require 'daemons'

#include Daemonize

#daemonize(STDOUT)

# ALL UDP PACKETS TO MYSQL # 
@db = Mysql::new("127.0.0.1","ruby","suga","ruby")
@mysql_date = Time.now
@table_name = @mysql_date.strftime("%Y%m%d-%H%M%S")
#p @table_name
sql = "CREATE TABLE `ruby`.`#{@table_name}-alludp` (`number` INT NOT NULL DEFAULT NULL AUTO_INCREMENT PRIMARY KEY ,`time` DATETIME NOT NULL ,`l4_protocol` TEXT DEFAULT NULL ,`protocol` TEXT DEFAULT NULL ,`source_ip` INT UNSIGNED NOT NULL ,`destination_ip` INT UNSIGNED NOT NULL ,`source_port` INT NOT NULL ,`destination_port` INT NOT NULL ,`length` INT NOT NULL ,`data` LONGBLOB) ENGINE = MYISAM"
@db.query(sql)

#dev = Pcap.lookupdev
if ARGV[0] then
  dev = ARGV[0]
else
  dev = "en2"
end
cap = Pcap::Capture.open_live(ARGV[0])
#cap.setfilter(ARGV[0]) #setfilterはすごく重い・・・

cap.loop do |pkt|
  #print pkt, "\n"
  #print pkt.raw_data, "\n"

  # ALL UDP PACKETS TO MYSQL # 
  if(Time.now.day != @mysql_date.day)
    @mysql_date = Time.now
    @table_name = @mysql_date.strftime("%Y%m%d-%H%M%S")
    sql = "CREATE TABLE `ruby`.`#{@table_name}-alludp` (`number` INT NOT NULL DEFAULT NULL AUTO_INCREMENT PRIMARY KEY ,`time` DATETIME NOT NULL ,`l4_protocol` TEXT DEFAULT NULL ,`protocol` TEXT DEFAULT NULL ,`source_ip` INT UNSIGNED NOT NULL ,`destination_ip` INT UNSIGNED NOT NULL ,`source_port` INT NOT NULL ,`destination_port` INT NOT NULL ,`length` INT NOT NULL ,`data` LONGBLOB) ENGINE = MYISAM ;"
    @db.query(sql)
  end
  if pkt.udp?
    time = pkt.time.strftime("%Y%m%d%H%M%S")
    src_ip = pkt.ip_src.to_i
    dst_ip = pkt.ip_dst.to_i
    src_port = pkt.sport
    dst_port = pkt.dport
    length = pkt.ip_len
    data = pkt.udp_data
    sql = "INSERT INTO `#{@table_name}-alludp` (`number` ,`time` ,`source_ip` ,`destination_ip` ,`source_port` ,`destination_port` ,`length`, `data`)VALUES (NULL , '#{time}', '#{src_ip}', '#{dst_ip}', '#{src_port}', '#{dst_port}', '#{length}', NULL)"
      @db.query(sql)
  end
end
cap.close
sock.close
