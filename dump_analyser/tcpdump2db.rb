# -*- coding: utf-8 -*-
require 'pcap'
require 'mysql'

#print 'Host:'
#host = STDIN.gets
#print 'id:'
#id = STDIN.gets
#print 'pass:'
#system "stty -echo"
#pass = $stdin.gets.chop
#system "stty echo"

@db = Mysql::new(ARGV[1],"ruby","suga0329","tcpdump")
@table_name = File::basename(ARGV[0])

@filename = ARGV[0]

sql = "CREATE TABLE `tcpdump`.`#{@table_name}` (`number` INT NOT NULL DEFAULT NULL AUTO_INCREMENT PRIMARY KEY ,`time` DATETIME NOT NULL ,`protocol_1` TEXT DEFAULT NULL ,`protocol_2` TEXT DEFAULT NULL ,`protocol_3` TEXT DEFAULT NULL ,`protocol_4` TEXT DEFAULT NULL ,`eth_src` TEXT DEFAULT NULL ,`eth_dst` TEXT DEFAULT NULL , `ip_src` INT UNSIGNED DEFAULT NULL ,`ip_dst` INT UNSIGNED DEFAULT NULL ,`tcp_srcport` INT DEFAULT NULL ,`tcp_dstport` INT DEFAULT NULL ,`udp_srcport` INT DEFAULT NULL,`udp_dstport` INT DEFAULT NULL, `length` INT DEFAULT NULL) ENGINE = MYISAM"
@db.query(sql)


result = `tshark -r #{@filename} -T fields -e frame.time -e frame.protocols -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e frame.len -E separator=\\;`

lines = result.rstrip.split(/\r?\n/).map {|line| line.chomp }

lines.each do |line|
  frame_prop = line.split(";")
  month = frame_prop[0].split(",")[0].split(" ")[0]#後回し
  day = frame_prop[0].split(",")[0].split(" ")[1]
  year = frame_prop[0].split(",")[1].split(" ")[0]
  hour = frame_prop[0].split(",")[1].split(" ")[1].split(":")[0]
  minute = frame_prop[0].split(",")[1].split(" ")[1].split(":")[1]
  second =  frame_prop[0].split(",")[1].split(" ")[1].split(":")[2].split(".")[0]
  frame_time = Time.local(year, month, day, hour, minute, second)
  frame_protocols = frame_prop[1].split(":")
  eth_src = frame_prop[2]
  eth_dst = frame_prop[3]
  ip_src = frame_prop[4]
  ip_dst = frame_prop[5]
  tcp_srcport = frame_prop[6]
  tcp_dstport = frame_prop[7]
  udp_srcport = frame_prop[8]
  udp_dstport = frame_prop[9]
  length = frame_prop[10]
  sql_insert = {
    "time" => frame_time.strftime("%Y%m%d%H%M%S"),
    "protocol_1" => frame_protocols[0],
    "protocol_2" => frame_protocols[1],
    "protocol_3" => frame_protocols[2],
    "protocol_4" => frame_protocols[3],
    "eth_src" => eth_src,
    "eth_dst" => eth_dst,
    "ip_src" => ip_src,
    "ip_dst" => ip_dst,
    "tcp_srcport" => frame_prop[6],
    "tcp_dstport" => frame_prop[7],
    "udp_srcport" => frame_prop[8],
    "udp_dstport" => frame_prop[9],
    "length" => length
  }
  sql = "INSERT INTO `#{@table_name}` ("
  cnt = 0
  sql_insert.each do |key, value|
    if value != "" && value != nil
      sql += ", " if cnt != 0
      sql += "`#{key}`"
      cnt +=1
    end
  end
  sql += ")VALUES ("
  cnt = 0
  sql_insert.each do |key, value|
    if value != "" && value != nil
      sql += ", " if cnt != 0
      if key.index("ip_")
        sql += "INET_ATON(\"#{value}\")"
      else
        sql += "'#{value}'"
      end
      cnt +=1
    end
  end
  sql += ")"
  p sql
  #sql = "INSERT INTO `#{@table_name}` (`number` ,`time` ,`protocol` ,`source_ip` ,`destination_ip` ,`source_port` ,`destination_port` ,`length`)VALUES (NULL , '#{time}', 'tcp','#{src_ip}', '#{dst_ip}', '#{src_port}', '#{dst_port}', '#{length}')"
  #sql = "INSERT INTO `#{@table_name}` (`time` ,`protocol_1`, `protocol_2` , `protocol_3, `protocol_4`, `eth_src`, `eth_dst`, `ip_src`, `ip_dst`, `tcp_srcport`, `tcp_dstport`, `udp_srcport`, `udp_dstport`, `length`)VALUES ('#{frame_time}', '#{frame_protocols[0]}', '#{frame_protocols[1]}', '#{frame_protocols[2]}', '#{frame_protocols[3]}', '#{eth_src}', '#{eth_dst}', '#{ip_src}', '#{ip_dst}', '#{tcp_srcport}', '#{tcp_dstport}', '#{udp_srcport}', '#{udp_dstport}', '#{frame_len}')"
  @db.query(sql)
end



#cap = Pcap::Capture.open_offline(ARGV[0])

#cap.loop do |pkt|
#  if pkt.tcp?
#    time = pkt.time.strftime("%Y%m%d%H%M%S")
#    src_ip = pkt.ip_src.to_i
#    dst_ip = pkt.ip_dst.to_i
#    src_port = pkt.sport
#    dst_port = pkt.dport
#    length = pkt.ip_len
#    sql = "INSERT INTO `#{@table_name}` (`number` ,`time` ,`protocol` ,`source_ip` ,`destination_ip` ,`source_port` ,`destination_port` ,`length`)VALUES (NULL , '#{time}', 'tcp','#{src_ip}', '#{dst_ip}', '#{src_port}', '#{dst_port}', '#{length}')"
#  elsif pkt.udp?
#    time = pkt.time.strftime("%Y%m%d%H%M%S")
#    src_ip = pkt.ip_src.to_i
#    dst_ip = pkt.ip_dst.to_i
#    src_port = pkt.sport
#    dst_port = pkt.dport
#    length = pkt.ip_len
#    sql = "INSERT INTO `#{@table_name}` (`number` ,`time` ,`protocol` ,`source_ip` ,`destination_ip` ,`source_port` ,`destination_port` ,`length`)VALUES (NULL , '#{time}', 'udp','#{src_ip}', '#{dst_ip}', '#{src_port}', '#{dst_port}', '#{length}')"
#  else
#    next
#  end
#  @db.query(sql)
#end
