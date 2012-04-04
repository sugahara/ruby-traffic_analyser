require 'mysql'

@db = Mysql::new("127.0.0.1","ruby","suga0329","tcpdump")
@table_name = ARGV[0]
DELTA_T = ARGV[1].to_f
sql = "SELECT time from `#{@table_name}` where number = '1'"

start_time = @db.query(sql).fetch_row()[0]

year = start_time.split(" ")[0].split("-")[0]
month = start_time.split(" ")[0].split("-")[1]
day = start_time.split(" ")[0].split("-")[2]
hour = start_time.split(" ")[1].split(":")[0]
min = start_time.split(" ")[1].split(":")[1]
sec = start_time.split(" ")[1].split(":")[2]

start_time = Time.local(year, month, day, hour, min, sec)
end_time = start_time + DELTA_T - 1

sql = "SELECT time FROM `#{@table_name}` WHERE number = (select max(number) from `#{@table_name}`)"
last_packet_time = @db.query(sql).fetch_row()[0]
#last_packet_time = 
year = last_packet_time.split(" ")[0].split("-")[0]
month = last_packet_time.split(" ")[0].split("-")[1]
day = last_packet_time.split(" ")[0].split("-")[2]
hour = last_packet_time.split(" ")[1].split(":")[0]
min = last_packet_time.split(" ")[1].split(":")[1]
sec = last_packet_time.split(" ")[1].split(":")[2]
last_packet_time = Time.local(year, month, day, hour, min, sec)

while end_time <= last_packet_time
  # ALL PROTOCOL
  #sql = "SELECT COUNT(DISTINCT source_ip, destination_ip, source_port, destination_port) FROM `#{@table_name}` WHERE time BETWEEN '#{start_time.strftime("%Y-%m-%d %H:%M:%S")}' AND '#{end_time.strftime("%Y-%m-%d %H:%M:%S")}'"

  # NOT WOL
  #sql = "SELECT COUNT(DISTINCT source_ip, destination_ip, source_port, destination_port) FROM `#{@table_name}` WHERE time BETWEEN '#{start_time.strftime("%Y-%m-%d %H:%M:%S")}' AND '#{end_time.strftime("%Y-%m-%d %H:%M:%S")}' AND source_port != 9 AND destination_port != 9 AND protocol = 'udp'"

  #NOT WOL Packets
  #sql = "SELECT COUNT(*) FROM `#{@table_name}` WHERE time BETWEEN '#{start_time.strftime("%Y-%m-%d %H:%M:%S")}' AND '#{end_time.strftime("%Y-%m-%d %H:%M:%S")}' AND source_port != 9 AND destination_port != 9 AND protocol = 'udp'"
  #TCP, UDP
  sql = "SELECT COUNT(DISTINCT source_ip, destination_ip, source_port, destination_port) FROM `#{@table_name}` WHERE time BETWEEN '#{start_time.strftime("%Y-%m-%d %H:%M:%S")}' AND '#{end_time.strftime("%Y-%m-%d %H:%M:%S")}' and protocol='udp'"
  #puts @db.query(sql).num_rows()
  puts @db.query(sql).fetch_row()
  start_time = end_time + 1
  end_time = start_time + DELTA_T - 1
end
