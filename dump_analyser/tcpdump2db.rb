require 'pcap'
require 'mysql'

print 'Host:'
host = STDIN.gets
print 'id:'
id = STDIN.gets
print 'pass:'
system "stty -echo"
pass = $stdin.gets.chop
system "stty echo"
@db = Mysql::new(host,id,pass,"tcpdump")
@table_name = File::basename(ARGV[0])

def new_table(pkt)
  time = pkt.time.strftime("%Y%m%d%H%M%S")
  table_name = "#{pkt.time.strftime("%Y%m%d")}"
  p table_name
end


sql = "CREATE TABLE `tcpdump`.`#{@table_name}` (`number` INT NOT NULL DEFAULT NULL AUTO_INCREMENT PRIMARY KEY ,`time` DATETIME NOT NULL ,`l4_protocol` TEXT DEFAULT NULL ,`protocol` TEXT DEFAULT NULL ,`source_ip` INT UNSIGNED NOT NULL ,`destination_ip` INT UNSIGNED NOT NULL ,`source_port` INT NOT NULL ,`destination_port` INT NOT NULL ,`length` INT NOT NULL) ENGINE = MYISAM"

@db.query(sql)

cap = Pcap::Capture.open_offline(ARGV[0])

cap.loop do |pkt|
  if pkt.tcp?
    time = pkt.time.strftime("%Y%m%d%H%M%S")
    src_ip = pkt.ip_src.to_i
    dst_ip = pkt.ip_dst.to_i
    src_port = pkt.sport
    dst_port = pkt.dport
    length = pkt.ip_len
    sql = "INSERT INTO `#{@table_name}` (`number` ,`time` ,`protocol` ,`source_ip` ,`destination_ip` ,`source_port` ,`destination_port` ,`length`)VALUES (NULL , '#{time}', 'tcp','#{src_ip}', '#{dst_ip}', '#{src_port}', '#{dst_port}', '#{length}')"
  elsif pkt.udp?
    time = pkt.time.strftime("%Y%m%d%H%M%S")
    src_ip = pkt.ip_src.to_i
    dst_ip = pkt.ip_dst.to_i
    src_port = pkt.sport
    dst_port = pkt.dport
    length = pkt.ip_len
    sql = "INSERT INTO `#{@table_name}` (`number` ,`time` ,`protocol` ,`source_ip` ,`destination_ip` ,`source_port` ,`destination_port` ,`length`)VALUES (NULL , '#{time}', 'udp','#{src_ip}', '#{dst_ip}', '#{src_port}', '#{dst_port}', '#{length}')"
  else
    next
  end
  @db.query(sql)
end
