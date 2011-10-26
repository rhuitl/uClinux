#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if ( isnull(NESSUS_VERSION) ) exit(0);

if(description)
{
 script_id(10287);
# script_cve_id("CVE-MAP-NOMATCH");
 script_version ("$Revision: 1.43 $");
 name["english"] = "Traceroute";
 name["francais"] = "Traceroute";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "Makes a traceroute to the remote host.

Risk factor : Low";

 desc["francais"] = "Fait un traceroute sur l'hote distant";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "traceroute";
 summary["francais"] = "traceroute";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");


dport = get_host_open_port();
if(!dport)dport = 80;

ip_id = rand() % 65535;

my_sport = rand() % 64000 + 1024;

finished = 0;
ttl = 1;
src = this_host();
dst = get_host_ip();
error = 0;

str_ip = string(dst);
z = strstr(str_ip, ".");

#
# pcap filtter
#

if(islocalhost())
{
# don't show route when no request was attempted
#dub report = string("For your information, here is the traceroute to ", dst, " : \n", dst);
#dub security_note(port:0, protocol:"udp", data:report);
 exit(0);
}
report = string("For your information, here is the traceroute from ", src, " to ", dst, " : \n", this_host(), "\n");
filter = string("dst host ", src, " and ((icmp and ((icmp[0]=3) or (icmp[0]=11)))" + 
		" or (src host ", get_host_ip(), " and tcp and tcp[0:2]=", dport, " and tcp[2:2]=", my_sport, " and (tcp[13]=4 or tcp[13]=18)))");

debug_print(level: 2, 'Filter=', filter, '\n');
d = get_host_ip();
prev = string("");

#
# the traceroute itself
#

function filter(p)
{
 local_var ip, proto, id, hl, tcp, port;
 
 proto = get_ip_element(ip:p, element:"ip_p");
 if(proto == IPPROTO_ICMP)
 {
  hl = get_ip_element(ip:p, element:"ip_hl");
  ip = substr(p, hl * 4 + 8, hl * 4 + 8 + 20);
  dst = get_ip_element(ip:ip, element:"ip_dst");
  id  = get_ip_element(ip:ip, element:"ip_id");
  if (id != ip_id ) { return 1; }
	
  if(dst == get_host_ip())return 0;
  else return 1;
 }
 else if(proto == IPPROTO_TCP )
 {
  hl = get_ip_element(ip:p, element:"ip_hl");
  tcp = substr(p, hl * 4, strlen(p));
  port = ord(tcp[2])*256 + ord(tcp[3]);
  if(port != my_sport )
  	{
  	return 1;
	}
  else return 0;
 }
 return 1;
}


function make_pkt(ttl, proto)
{
  #proto = proto % 5;
  #display("make_pkt(", ttl, ", ", proto, ")\n");
  src = this_host();
  
  
   # Prefer TCP
   if( proto == 0 || proto > 2)
   {
    ip = forge_ip_packet(ip_v : 4, ip_hl:5, ip_tos:0, ip_id:ip_id,
			ip_len:20, ip_off:0, ip_p:IPPROTO_TCP, 
			ip_src:src, ip_ttl:ttl);
 
    p = forge_tcp_packet(ip:ip, th_sport:my_sport, th_dport: dport, 
			th_flags: TH_SYN, th_seq: ttl,
			th_ack: 0, th_x2    : 0,th_off   : 5,
			th_win   : 2048, th_urp   : 0);
   
   }
   
   
  # then UDP
  if (proto == 1)
  {
    ip = forge_ip_packet(ip_v : 4, ip_hl:5, ip_tos:0, ip_id:ip_id,
			ip_len:28, ip_off:0, ip_p:IPPROTO_UDP, 
			ip_src:src, ip_ttl:ttl);
    p = forge_udp_packet(ip:ip, uh_sport:my_sport, uh_dport:32768, uh_ulen:8);
    return (p);
  }
  # then ICMP
  if (proto == 2)
  {
    ip = forge_ip_packet(ip_v : 4, ip_hl:5, ip_tos:0, ip_id:ip_id,
			ip_len:20, ip_off:0, ip_p:IPPROTO_ICMP, 
			ip_src:src, ip_ttl:ttl);
    p = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
			icmp_seq: ttl, icmp_id:ttl);
    return (p);
  }
 
    return (p);
}

proto=0;	# Prefer TCP
gateway_n = 0;

while(!finished)
{

 for (i=0; i < 3; i=i+1)
 {
  err=1;
  p = make_pkt(ttl: ttl, proto: proto);
  rep = send_packet(p, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
  then = unixtime();
  while(rep)
  {
   if ( unixtime() - then > 5 ) {
	rep = NULL;
	break;
   }
   if(filter(p:rep) != 0 ) { 
   	rep = pcap_next(pcap_filter:filter, timeout:1);
 	}
 	else break;
  }
  
  
  if(rep)
  {
   psrc = get_ip_element(ip:rep, element:"ip_src");
   #display("+", psrc, "\n");
   gateway[gateway_n ++] = psrc;
   d = psrc - d;
   if(!d)finished = 1;
   d = get_host_ip();
   error = 0; err=0;
   i=666;
  }
  else
  {
   proto++; 
   if(proto >= 3)err = 1;
   else err = 0;
   proto%=3;
  }
 }
 if(err)
 {
  #display("...\");
  if (!error) gateway[gateway_n++] = '?';
  error = error+1;
 }
 ttl = ttl+1;

 #
 # If we get more than 3 errors one after another, we stop
 #
 if(error > 3)finished = 1;
 
 #
 # Should not get here
 #
 if(ttl > 50)finished = 1;
}

max = 0;
for (i = 1; i < max_index(gateway); i ++)
 if (gateway[i] != gateway[i-1])
  max = i;
 else
  debug_print('Duplicate router #', i, '(', gateway[i], ') in trace to ', get_host_ip(), '\n');

for (i = 0; i <= max; i ++)
 report = strcat(report, gateway[i], '\n');

#
# show if at least one route was obtained.
#
# MA 2002-08-15: I split the expression "ttl=ttl-(1+error)" because of 
# what looked like a NASL bug
y = 1 + error;
ttl = ttl - y;
if (ttl > 0)
security_note(port:0, protocol:"udp", data:report);
