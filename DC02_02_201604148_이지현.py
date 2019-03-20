import socket
import struct


recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

def convert_ethernet_address(data):
	ethernet_addr = list()
	for i in data:
		ethernet_addr.append(i.hex())
	ethernet_addr = ":".join(ethernet_addr)
	return ethernet_addr

while True:

	data = recv_socket.recvfrom(20000)

	ethernet_hrd = data[0][0:14]
	ethernet_header = struct.unpack("!6c6c2s", ethernet_hrd)
	ether_src = convert_ethernet_address(ethernet_header[0:6])
	ether_dest = convert_ethernet_address(ethernet_header[6:12])
	ip_header = "0x"+ethernet_header[12].hex()

	print("=====ethernet header=====")
	print("src_mac_address:", ether_src)
	print("dest_mac_address:", ether_dest)
	print("ip_version", ip_header)


	ip_hrd = data[0][14:34]
	ip_head = struct.unpack("!1s1sHH2sBB2s4s4s", ip_hrd)
	ver_head_length = ip_head[0].hex()
	ver_length= str(ver_head_length)
	dsc_ecn = ip_head[1].hex()
	r_dsc_ecn = str(dsc_ecn)	 	
	total_length = ip_head[2]
	identification  = ip_head[3]	
	flags = "0x"+ ip_head[4].hex()
	str_flags = str(ip_head[4].hex())
	ttl = ip_head[5]
	prt = ip_head[6]
	protocol = str(prt)	
	hc = "0x"+ ip_head[7].hex()
	src_ip = socket.inet_ntoa(ip_head[8])
	dst_ip = socket.inet_ntoa(ip_head[9])

	print("=====ip_header=====")
	print("ip_version: ", ver_length[0])	
	print("ip_length: ", ver_length[1])
	print("differentiated_service_codepoint: ", r_dsc_ecn[0])
	print("explicit_cingestion_notificarion: ", r_dsc_ecn[1])
	print("total_length: ", total_length)	
	print("identification: ", identification)
	print("flags: ", flags)
	print(">>>reserved_bit: 0")
	print(">>>not_fragments: ", str_flags[1])
	print(">>>fragments: ", str_flags[2])
	print(">>>fragment_offset: ", str_flags[3])
	print("Time_to_live: ", ttl)
	print("protocol: ", protocol)
	print("header_checksum: ", hc)
	print("source_ip_address: ", src_ip)
	print("dest_ip_address: ", dst_ip)
	

	if protocol == "6":
		tcp_head = data[0][34:54]
		tcp_hdr = struct.unpack("!HHII2sH2sH", tcp_head )
		src_port = tcp_hdr[0]
		dec_port = tcp_hdr[1]
		seg_num = str(tcp_hdr[2])
		ack_num = str(tcp_hdr[3])
		header_len = tcp_hdr[4].hex()
		header_len_convert = str(header_len)
		flags = data[0][47] 
		window_size_value = str(tcp_hdr[5])
		checksum ="0x"+ tcp_hdr[6].hex()
		urgent_pointer = tcp_hdr[7]

	
		print("=====tcp_header=====")
		print("src_port: ", src_port)	
		print("dec_port: ", dec_port)
		print("seg_num: ", seg_num)
		print("ack_num: ", ack_num)
		print("header_len: ", header_len_convert[0])
		print("flags: ", flags)
		print("window_size_value: ", window_size_value)
		print("checksum: ", checksum)
		print("urgent_pointer: ", urgent_pointer)

	if protocol == "17":
		udp_head = data[0][34:42]		
		udp_hdr = struct.unpack("!HHHH", udp_head)
		src_port = udp_hdr[0]
		dec_port = udp_hdr[1]
		length = udp_hdr[2]
		checksum ="0x"+str(udp_hdr[3])

		print("=====udp_header=====")
		print("src_port: ", src_port)
		print("dec_port: ", dec_port)
		print("length: ", length)
		print("checksum: ", checksum)




