# -*- Fundamental -*-
#
# This NASL script was written by Martin O'Neal of Corsaire 
# (http://www.corsaire.com)
# 
# The script provides basic tftp functionality for use in other scripts...
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.
#
# GPLv2
# 




############## declarations ################


# declare function
function tftp_get(port,path)
{
	# initialise variables
	local_var request_data;
	local_var request_ip;
	local_var request_udp;
	local_var response_udp;
	local_var response_data;
	local_var filter;
	local_var source_port;
	local_var destination_port;
	source_port=23793+int((rand()%6157));
	destination_port=port;
		
	# create request
	request_data=raw_string(0x00,0x01)+path+raw_string(0x00)+'octet'+raw_string(0x00);
	request_ip=forge_ip_packet(ip_hl:5,ip_v:4,ip_tos:0,ip_len:20,ip_id:rand(),ip_off:0,ip_ttl:64,ip_p:IPPROTO_UDP,ip_src:this_host());
	request_udp=forge_udp_packet(ip:request_ip,uh_sport:source_port,uh_dport:destination_port,uh_ulen:8+strlen(request_data),data:request_data);

	# create filter
	filter='udp and dst port '+source_port+' and src host '+get_host_ip();

	# send packet
	response_udp=send_packet(request_udp,pcap_active:TRUE,pcap_filter:filter);	

	# check if response received
	if(response_udp)
	{
		# retrieve udp data
		response_data=get_udp_element(udp:response_udp,element:"data");
		
		# check if udp data is valid positive tftp data response
		if(ord(response_data[0])==0x00 && ord(response_data[1])==0x03 && ord(response_data[2])==0x00 && ord(response_data[3])==0x01)
		{
			# remove tftp protocol header from data
			response_data=substr(response_data,4);
			
			return(response_data);
		}
	}
	
	return NULL;
}



# declare function
function tftp_put(port,path)
{
	# initialise variables
	local_var request_data;
	local_var request_ip;
	local_var request_udp;
	local_var response_udp;
	local_var response_data;
	local_var filter;
	local_var source_port;
	local_var destination_port;
	source_port=32288+int((rand()%7354));
	destination_port=port;
		
	# create request
	request_data=raw_string(0x00,0x02)+path+raw_string(0x00)+'octet'+raw_string(0x00);
	request_ip=forge_ip_packet(ip_hl:5,ip_v:4,ip_tos:0,ip_len:20,ip_id:rand(),ip_off:0,ip_ttl:64,ip_p:IPPROTO_UDP,ip_src:this_host());
	request_udp=forge_udp_packet(ip:request_ip,uh_sport:source_port,uh_dport:destination_port,uh_ulen:8+strlen(request_data),data:request_data);

	# create filter
	filter='udp and dst port '+source_port+' and src host '+get_host_ip();

	# send packet
	response_udp=send_packet(request_udp,pcap_active:TRUE,pcap_filter:filter);	

	# check if response received
	if(response_udp)
	{
		# retrieve udp data
		response_data=get_udp_element(udp:response_udp,element:"data");
		
		# check if udp data is valid positive tftp data response
		if(ord(response_data[0])==0x00 && ord(response_data[1])==0x04 && ord(response_data[2])==0x00 && ord(response_data[3])==0x00)
		{
			return(TRUE);
		}
	}
	
	return NULL;
}


