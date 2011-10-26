#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10663);
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "DHCP server info gathering";
 name["francais"] = "Obtention d'informations auprès de DHCP";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This script contacts the remote DHCP server (if any) and
attempts to retrieve information about the network layout.

Some DHCP server provide sensitive information such
as the NIS domain name, or network layout information
such as the list of the network www servers, and so on.

It does not demonstrate any vulnerability, but
a local attacker may use DHCP to become intimately familiar
with the network in no time.

Solution : Apply filtering to keep this information off the network
Risk factor : Low";




 script_description(english:desc["english"]);
 
 summary["english"] = "Chats with the remote DHCP server";
 summary["francais"] = "Discute avec le serveur DHCP distant";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#


if(islocalhost())exit(0);


#-----------------------------------------------------#
# Data extraction functions                           #
#-----------------------------------------------------#

function extract_ip(data, index)
{
 ip_a = ord(data[index+2]);
 ip_b = ord(data[index+3]);
 ip_c = ord(data[index+4]);
 ip_d = ord(data[index+5]);
 return(string(ip_a, ".", ip_b, ".", ip_c, ".", ip_d));
}


function extract_multiple_ips(data, i)
{
 num_ips = ord(data[i+1]);
 num_ips = num_ips / 4;
 ret = "";
 sp = "";
 for(_i = 0; _i < num_ips ; _i = _i + 1)
 {
  off = _i * 4;
  ret = string(ret, sp, extract_ip(data:data, index:i+off));
  sp = " , ";
 }
 ret = string(ret, "\n");
 return(ret);
}

function extract_string(data, i)
{
 len = ord(data[i+1]);
 ret ="";
 for(_i = 0 ; _i < len ; _i = _i + 1)
 {
  ret = string(ret, data[i+2+_i]);
 }
 return(ret);
}


#----------------------------------------------------------#
# Forgery                                                  #
#----------------------------------------------------------#


# Options we are interested in seeing.

opts = raw_string(1, 3, 4, 5, 6, 7, 8, 9, 
		  10, 11, 12, 14, 15, 16, 
		  17, 19, 20, 28, 40, 41, 
		  42, 44, 45, 48, 49, 54, 
		  64, 65, 66, 67, 68, 69, 
		  70, 71, 72, 73, 74, 75, 76);


len = strlen(opts);



#
# Note that we lie to the remote DHCP server by telling
# it our ether address is FF:FF:FF:FF:FF. We do that 
# so that we can get a reply from the server (nasl
# does not know how to extract one's MAC address yet)
#
#


mac = raw_string(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);


# (we choose a random request id)
a = rand() % 255;
b = rand() % 255;
c = rand() % 255;
d = rand() % 255;


req = raw_string(
	0x01, 0x01, 0x06, 0x00, a,    b,    c,    d,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + mac + 
	raw_string( 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
	0x53, 0x63, 0x35, 0x01, 0x01, 0x37, len) + opts +
	raw_string( 
	0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00);
	
len = strlen(req);
addr = this_host();

ip = forge_ip_packet(
		ip_v    : 4,
		ip_hl   : 5,
		ip_len  : 20 + 8 + len,
		ip_id   : 0x1234,
		ip_p    : IPPROTO_UDP,
		ip_tos  : 0,
		ip_ttl  : 0x40,
		ip_off  : 0,
		ip_src  : addr);
		
udp = forge_udp_packet(
		ip	: ip,
		uh_sport: 68,
		uh_dport: 67,
		uh_ulen : 8 + len,
		data    : req);
		

#
# Removing the 'src host' part of the pcap filter may be wise, 
# as some DHCP server  will ask another agent to reply for them. But 
# if we do that, we may encounter some problems when the same plugin is 
# started against two hosts at the same time, and in addition to
# this, we want to test this remote server, not another one.
#		
filter = string("udp and src host ", get_host_ip(), " and src port ", 67,
		" and dst port ", 68);
		
rep = send_packet(udp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:3);		
if(rep)
{
#
# Woowoo. We received something back.
#
set_kb_item(name:"DHCP/Running", value:TRUE);
data = get_udp_element(element:"data", udp:rep);
if(strlen(data) < 14)exit(0);
my_ip = extract_ip(data:data, index:14);
master_dhcp = extract_ip(data:data, index:18);
report = string("Master DHCP server of this network : ", master_dhcp, "\n");
report = string(report, "IP address the DHCP server would attribute us : ", my_ip, "\n");


#
# Now, we read the options we requested.
#
start = 240;
end   = strlen(data);
if(end < start)exit(0);

for(i = start; i < end ;)
{
 opt = ord(data[i]);
 if(opt == 255){
 	i = end + 1;
	}
 else
 {
  #
  # Netmask
  #
  if(opt == 1)
  {
   report = string(report, "netmask = ", extract_ip(data:data, index:i), "\n");
  }
 
 
  #
  # Router
  #
  if(opt == 3)
  {
   report = string(report, "router = ", extract_multiple_ips(data:data, i:i));
  }
  
  
  #
  # Time server(s)
  #
  if(opt == 4)
  {
   report = string(report, "time server(s) = ", extract_multiple_ips(data:data, i:i));
  }
  
 
  #
  # NS
  #
  if(opt == 5)
  {
   report = string(report, "name server(s) = ", extract_multiple_ips(data:data, i:i));
  }
  
  
  #
  # DNS
  #
  if(opt == 6)
  {
  report = string(report, "domain name server(s) = ", extract_multiple_ips(data:data, i:i));
  }
  
  #
  # Log server(s)
  #
  if(opt == 7)
  {
   report  = string(report, "log server(s) = ", extract_multiple_ips(data:data, i:i));
  }
 
  #
  # Cookie server(s)
  #
  if(opt == 8)
  {
   report = string(report, "cookie server(s) = ", extract_multiple_ips(data:data, i:i));
  }
  
  #
  # Print server(s)
  #
  if(opt == 9)
  {
   report = string(report, "print server(s) = ", extract_multiple_ips(data:data, i:i));
  }
  
  #
  # Impress server(s)
  #
  if(opt == 10)
  {
   report = string(report, "impress server(s) = ", extract_multiple_ips(data:data, i:i));
  }
  
  
  #
  # Resource location server(s)
  #
  if(opt == 11)
  {
   report = string(report, "resource location server(s) = ", extract_multiple_ips(data:data, i:i));
  }
  
  #
  # Host name
  #
  if(opt == 12)
  {
   len = ord(data[i+1]);
   name = "";
   for(k = 0; k < len ; k = k + 1)
   {
    name = string(name, data[i+2+k]);
   }
   report = string(report, "host name = ", name, "\n");
  }
  
  
  #
  # dump file
  #
  if(opt == 14)
  {
   len = ord(data[i+1]);
   name = "";
   for(k = 0; k < len ; k = k + 1)
   {
    name = string(name, data[i+2+k]);
   }
   report = string(report, "dump file name = ", name, "\n");
  }
  
  
  #
  # Domain name
  #
  if(opt == 15)
  {
   len = ord(data[i+1]);
   domain = "";
   for(k = 0; k < len ; k = k + 1)
   {
    domain = string(domain, data[i+2+k]);
   }
   report = string(report, "domain name = ", domain, "\n");
  }
  
 
  #
  # swap server
  #
  if(opt == 16)
  {
   report = string(report, "swap server = ", extract_ip(data:data, index:i));
  }
  
  
  #
  # Root path
  #
  if(opt == 17)
  {
   len = ord(data[i+1]);
   name = "";
   for(k = 0; k < len ; k = k + 1)
   {
    name = string(name, data[i+2+k]);
   }
   report = string(report, "root path  = ", name, "\n");
  }
  
  #
  # IP forwarding enabled ?
  #
  if(opt == 19)
  {
   if(ord(data[i+2]))report = string(report, 
   "The remote DHCP server wants its clients to foward IP packets\n");
  }
  
  if(opt == 20)
  {
   if(ord(data[i+2]))report = string(report,
  "The remote DHCP server wants its clients to forward source routed packets\n");
  }
  
  #
  # Broadcast
  #
  if(opt == 28)
  {
  report = string(report, "broadcast address = ", extract_ip(data:data, index:i), "\n");
  }
  
  #
  # NIS domain name (woowoo ;)
  #
  if(opt == 40)
  {
   len = ord(data[i+1]);
   domain = "";
   for(k = 0; k < len ; k = k + 1)
   {
    domain = string(domain, data[i+2+k]);
   }
   report = string(report, "NIS domain name = ", domain, "\n");
   old_nis = get_kb_item("RPC/NIS/domain");
   if(!old_nis)set_kb_item(name:"RPC/NIS/domain", value:domain);
  }
  
  #
  # NIS server(s)
  #
  if(opt == 41)
  {
  report = string(report, "NIS server(s)  = ", extract_multiple_ips(data:data,   i:i));
  }
  
  #
  # NTP server(s)s
  #
  if(opt == 42)
  {
  report = string(report, "NTP server(s)  = ", extract_multiple_ips(data:data, 
   i:i));
  }
  
  
  #
  # NetBios DNS
  #
  if(opt == 44)
  {
  report = string(report, "Netbios Name server(s) = ", extract_multiple_ips(data:data,   i:i));
  }
 
  #
  # NetBios DNS
  #
  if(opt == 45)
  {
  report = string(report, "Netbios Datagram Distribution server(s) = ",
  extract_multiple_ips(data:data, i:i));
  }
  
  #
  # XWindow fonts server(s)
  #
  if(opt == 48)
  {
  report = string(report, "XWindow fonts server(s) = ",
  extract_multiple_ips(data:data, i:i));
  }
  
  #
  # XWindow display
  #
  if(opt == 49)
  {
  report = string(report, "XWindow Display server(s) = ",
  extract_multiple_ips(data:data, i:i));
  }
  
  #
  # DHCP server(s) identifier
  #
  if(opt == 54)
  {
  report = string(report, "DHCP server(s) identifier = ",
  extract_multiple_ips(data:data, i:i));
  }
  
  
  #
  # NIS+ domain name
  #
  if(opt == 64)
  {
   report = string(report, "NIS+ domain name = ",
   	extract_string(data:data, i:i), "\n");
  }
  
  
  
  #
  # NIS+ server(s)s
  #
  if(opt == 65)
  {
   report = string(report, "NIS+ server(s) = ",
   	extract_multiple_ips(data:data, i:i));
  }
  
  
  
  #
  # Boot server(s) host name
  #
  if(opt == 66)
  {
   report = string(report, "Bootserver(s) host name = ",
   	extract_string(data:data, i:i), "\n");
  }
  
  
  #
  # Bootfile name
  #
  if(opt == 67)
  {
   report = string(report, "Bootfile name = ",
   	extract_string(data:data, i:i), "\n");
  }
  
  
  
  
  #
  # Mobile IP home agents
  #
  if(opt == 68)
  {
   report = string(report, "Mobile IP home agents = ",
   	extract_multiple_ips(data:data, i:i));
  }
  
  
  
  #
  # SMTP server(s)s
  #
  if(opt == 69)
  {
   report = string(report, "SMTP server(s)s = ",
   	extract_multiple_ips(data:data, i:i));
  }
  
  
  #
  # POP3 server(s)s
  #
  if(opt == 70)
  {
   report = string(report, "POP3 server(s)s = ",
   	extract_multiple_ips(data:data, i:i));
  }
  
  
  
  #
  # NNTP server(s)s
  #
  if(opt == 71)
  {
   report = string(report, "NNTP server(s) = ",
   	extract_multiple_ips(data:data, i:i));
  }
  
  
  
  #
  # WWW server(s)s
  #
  if(opt == 72)
  {
   report = string(report, "WWW server(s) = ",
   	extract_multiple_ips(data:data, i:i));
  }
  
  
  #
  # Finger server(s)s
  #
  if(opt == 73)
  {
   report = string(report, "Finger server(s) = ",
   	extract_multiple_ips(data:data, i:i));
  }
  
  
  #
  # IRC server(s)s
  #
  if(opt == 74)
  {
   report = string(report, "IRC server(s)s = ",
   	extract_multiple_ips(data:data, i:i));
  }
  
  
  
  #
  # Street Talk server(s)s
  #
  if(opt == 75)
  {
   report = string(report, "StreetTalk server(s)s = ",
   	extract_multiple_ips(data:data, i:i));
  }
  
  
  
  #
  # Street Talk Directory Assistance server(s)s
  #
  if(opt == 76)
  {
   report = string(report, "StreetTalk Directory Assistance (STDA) server(s) = ",
   	extract_multiple_ips(data:data, i:i));
  }
   i = i + ord(data[i+1]) + 2;
  }
  
 }
 report = string("Here is the information we could gather from the remote DHCP\n",
"server. This allows an attacker on your local network to gain\n",
"information about it easily :\n\n", report, "\n\n",
"Solution : remove the options that are not in use in your DHCP server\n",
"Risk factor : Low\n");
 security_note(port:67, protocol:"udp", data:report);
}

