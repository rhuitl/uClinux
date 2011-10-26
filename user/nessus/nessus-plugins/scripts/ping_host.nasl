#TRUSTED 89002a57e77bd6f9018bf27c92892586d1ad9102ebcccf0ebd24c21874dd0721c0cd61644e240c63dd4996316adaa4a9ea7fe2475ef3c9d1d04df19d5449e012b3aa33b223a3a8d4f3d51e336dff119addf31fdb38edd82df910e93fdfbb3b1f2e3bea27bdc2d26a9ae469d16618a010509930e66ae7ea659f6a8bbb26cb6c65484bf6eab9e6977354a2611b88ce1641132962ea67dc12dbfeec3c6dd2479061441bfba21709f94a4b860bfdecd227f0baa5c243dd74a2fa8c4c36919ffb55c2183d92207a813807b0327ca7eb4c989478e78d406b13b73d2bc033f6c0f403062e41c69a98fcb30c84a13c549ad05960bf9366a774fa6421e14321b68a7523b103c73667fee5425f274fd49e4d2a89d1c7fae2bb5fe2bd0a87e6affb2f3a6acbcca6820954ae87d4c60c7f7a43dfa3a409b221b854c57833e39ff0be26e1cc8bc8af7d0cce9b7d912a942e99d7c0255017a156f9a96a745c00404f5c253d060dc6eeecd92a1ac0f9ed065829c209bd6879689a3d8a9be2f2626b21568998816c8983a44d393b975373a4234e81c99c0e3b8f6ce3039daf552947e7e7f57724ee399d66f70d578bdb1a52f20b4563a810f798b1f2b4792f0d919dea87e1d9291d7cffb5071e7e57b2c7a49698e8aa101e0cd1917d5a6f5d9346c65405c4d527928525dab29642d4653757afe57c0937b27126da0169f9dee08f2d22af0f5b86ca
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

#defportlist= "22;80;443";
defportlist= "built-in";
# Or try this one:
# defportlist= "113;139;445";

# MA 2005-05-01
# 'built-in' port list is defined in nasl_tcp_ping C function 
# (libnasl/nasl/nasl_packet_forgery.c). Currently it is 
# 139, 135, 445, 80, 22, 515, 23, 21, 6000, 1025, 25, 111, 1028, 9100, 
# 1029, 79, 497, 548, 5000, 1917
# The rest of the list is truncated on Nessus <= 2.2.4:
# 53, 161, 9001, 65535, 443, 113, 993, 8080

# H D Moore & Michel Arboi's Port list :
# if you want more reliable but slower results, use 'extended' as the port list
# 21, 22, 23, 25, 53, 79, 80, 110, 113, 135, 139, 143, 264, 389, 443, 445, 
# 993, 1454, 1723, 3389, 8080, 2869 (uPNP)


if(description)
{
 script_id(10180);
 script_version ("1.63");
 name["english"] = "Ping the remote host";
 name["francais"] = "Ping la machine distante";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This script will tcp ping the remote host and report to the plugins 
knowledge base whether the remote host is dead or alive.

The technique used is the TCP ping, that is, this script sends to the remote
host a packet with the flag SYN, and the host will reply with a RST or a 
SYN/ACK.

You can also select the use of the traditional ICMP ping.

Risk factor : None";

 desc["francais"] = "Ce script ping la
machine distante et rapporte dans
la base de connaissances des plugins
si la machine distante est éteinte
ou allumée.

La technique utilisée est le ping TCP,
c'est à dire que ce script envoye un
paquet TCP avec le flag ACK,
et la machine distante doit répondre
avec un RST.

Vous pouvez aussi selectionner le ping ICMP
traditionel.

Facteur de risque : Aucun";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "icmp/tcp pings the remote host";
 summary["francais"] = "Ping la machine distante via un ping tcp et/ou icmp";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_SCANNER);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Port scanners";
 family["francais"] = "Port scanners";
 script_family(english:family["english"], francais:family["francais"]);

 script_add_preference(name:"TCP ping destination port(s) :",
                       type:"entry", value:defportlist);
 if ( defined_func("inject_packet") )
  script_add_preference(name:"Do an ARP ping", 
                       type:"checkbox", value:"yes");

 script_add_preference(name:"Do a TCP ping", 
                      type:"checkbox", value:"yes");
 script_add_preference(name:"Do an ICMP ping", 
                      type:"checkbox", value:"no");		      
 script_add_preference(name:"Number of retries (ICMP) :", 
 			type:"entry", value:"6");	
 script_add_preference(name:"Do an applicative UDP ping (DNS,RPC...)", 
                      type:"checkbox", value:"no");
			
 script_add_preference(name:"Make the dead hosts appear in the report",
 			type:"checkbox", value:"no");
			
 script_add_preference(name:"Log live hosts in the report",
		      type:"checkbox", value:"no");			
 exit(0);
}

#
# The script code starts here
#

global_var log_live, do_tcp, do_arp, do_icmp, do_udp, test, show_dead;



# 
# Utilities
#
function mkbyte()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return raw_string(l & 0xff);
}

function mkword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return  raw_string((l >> 8) & 0xFF, l & 0xFF);
}

function mkipaddr()
{
 local_var ip;
 local_var str;

 ip = _FCT_ANON_ARGS[0];
 str = split(ip, sep:'.', keep:FALSE);
 return raw_string(int(str[0]), int(str[1]), int(str[2]), int(str[3])); 
}




#
# Global Initialisation
#
set_kb_item(name: "/tmp/start_time", value: unixtime());
do_arp = script_get_preference("Do an ARP ping");
if(!do_arp)do_arp = "yes";


do_tcp = script_get_preference("Do a TCP ping");
if(!do_tcp)do_tcp = "yes";

do_icmp = script_get_preference("Do an ICMP ping");
if(!do_icmp)do_icmp = "no"; # disabled by default (too slow)

do_udp = script_get_preference("Do an applicative UDP ping (DNS,RPC...)");
if (! do_udp) do_udp = "no";

test = 0;

show_dead = script_get_preference("Make the dead hosts appear in the report");
log_live = script_get_preference("Log live hosts in the report");
if ( "yes" >< show_dead ) set_kb_item(name: '/tmp/ping/show_dead', value:TRUE);
if ( "yes" >< log_live ) set_kb_item(name: '/tmp/ping/log_live', value:TRUE);





#
# Fortinet Firewalls act as an AV gateway. They do that
# by acting as a man-in-the-middle between the connection
# and the recipient. If there is NO recipient, then sending
# data to one of the filtered ports will result in a timeout.
#
# By default, Fortinet listens on port 21,25,80,110 and 143.
#
#
function check_fortinet_av_gateway()
{
 local_var soc, now, r;

 soc = open_sock_tcp(25, timeout:3);
 if ( !soc ) return 0;
 now = unixtime();
 r = recv_line(socket:soc, length:1024, timeout:5);
 if ( r || unixtime() - now < 4 ) return 0;
 close(soc);

  
 soc = open_sock_tcp(110, timeout:3);
 if ( ! soc ) return 0;
 now = unixtime();
 r = recv_line(socket:soc, length:1024, timeout:5);
 if ( r || unixtime() - now < 4 ) return 0;
 close(soc);

 soc = open_sock_tcp(143, timeout:3);
 if ( ! soc ) return 0;
 now = unixtime();
 r = recv_line(socket:soc, length:1024, timeout:5);
 if ( r || unixtime() - now < 4 ) return 0;
 close(soc);

 # ?
 soc = open_sock_tcp(80, timeout:3);
 if ( ! soc ) return 0;
 send(socket:soc, data:http_get(item:"/", port:80));
 now = unixtime();
 r = recv_line(socket:soc, length:1024, timeout:5);
 if ( r || unixtime() - now < 4 ) return 0;
 close(soc);
 

 return 1;
}



function check_riverhead_and_consorts()
{
 local_var ip, tcpip, i, flags, j, r;

   ip = forge_ip_packet(ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 40,
                        ip_id : rand() % 65535,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 175,
                        ip_off : 0,
			ip_src : this_host());



 for ( i = 0 ; i < 10 ; i ++ )
 {
    tcpip = forge_tcp_packet(ip       : ip,
                             th_sport : 63000 + i,
                             th_dport : 60000 + i,
                             th_flags : TH_SYN,
                             th_seq   : rand(),
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512);

    for ( j = 0 ; j < 3 ; j ++ )
    {
    r = send_packet(tcpip, pcap_active:TRUE, pcap_filter:"src host " + get_host_ip()+ " and dst host " + this_host() + " and src port " + int(60000 + i) + " and dst port " + int(63000 + i ), pcap_timeout:1);
    if ( r ) break;
    }
    if ( ! r ) return 0;
    flags = get_tcp_element(tcp:r, element:"th_flags");
    if( flags != (TH_SYN|TH_ACK) ) return 0;
 }

 security_note(data:"
The remote host seems to be a RiverHead device, or some sort of decoy (it 
returns a SYN|ACK for any port), so Nessus will not scan it. If you want 
to force a scan of this host, disable the 'ping' plugin and restart a 
scan.", port:0);
 return 1;
}

function difftime(t1, t2)
{
 local_var	s1, s2, u1, u2, v;

 v = split(t1, sep: '.', keep: 0);
 s1 = int(v[0]);
 u1 = int(v[1]);
 v = split(t2, sep: '.', keep: 0);
 s2 = int(v[0]);
 u2 = int(v[1]);
 return (u2 - u1) + (s2 - s1) * 1000000;
}

function log_live(rtt)
{
 #
 # Let's make sure the remote host is not a riverhead or one of those annoying
 # devices replying on every port
 #
 if ( check_fortinet_av_gateway() || check_riverhead_and_consorts() )
  set_kb_item(name:"Host/ping_failed", value:TRUE);

 #debug_print(get_host_ip(), " is up\n");
 if ("yes" >< log_live)
 {
  security_note(data:"The remote host is up", port:0);
 }
 if (rtt) set_kb_item(name: "/tmp/ping/RTT", value: rtt);
 #debug_print('RTT=', rtt, 'us\n');
 exit(0);
}


function log_dead()
{
 #debug_print(get_host_ip(), " is dead\n");
 if("yes" >< show_dead)
  security_note(data:"The remote host is considered as dead - not scanning", port:0);
 set_kb_item(name:"Host/ping_failed", value:TRUE);
 exit(0);
}
 

function arp_ping()
{
 local_var broadcast, macaddr, ethernet, arp, r, i, srcip, dstmac, t1, t2;

 if ( ! defined_func("inject_packet") ) return (0);
 if ( ! islocalnet()  || islocalhost() ) return(0);

 broadcast = crap(data:raw_string(0xff), length:6);
 macaddr   = get_local_mac_addr();

 if ( ! macaddr ) return 0;  # Not an ethernet interface

 arp       = mkword(0x0806); 


 ethernet = broadcast + macaddr + arp;

 arp      = ethernet +              			# Ethernet
           mkword(0x0001) +        			# Hardware Type
           mkword(0x0800) +        			# Protocol Type
           mkbyte(0x06)   +        			# Hardware Size
           mkbyte(0x04)   +        			# Protocol Size
           mkword(0x0001) +        			# Opcode (Request)
           macaddr        +        			# Sender mac addr
           mkipaddr(this_host()) + 			# Sender IP addr
           crap(data:raw_string(0), length:6) + 	# Target Mac Addr
           mkipaddr(get_host_ip());

 t1 = gettimeofday();
 for ( i = 0 ; i < 3 ; i ++ )
{
 r = inject_packet(packet:arp, filter:"arp and arp[7] = 2 and src host " + get_host_ip(), timeout:1);
 if ( r && strlen(r) > 31 ) 
  {
  t2 = gettimeofday();
  srcip = substr(r, 28, 31);
  if ( srcip == mkipaddr(get_host_ip() ) )
   {
    dstmac = substr(r, 6, 11);
    dstmac = strcat(hexstr(dstmac[0]), ":",
	            hexstr(dstmac[1]), ":",
		    hexstr(dstmac[2]), ":",
		    hexstr(dstmac[3]), ":",
		    hexstr(dstmac[4]), ":",
		    hexstr(dstmac[5]));
    set_kb_item(name:"ARP/mac_addr", value:dstmac);
    log_live(rtt: difftime(t1: t1, t2: t2));
    exit(0);
   }
  }
}
 log_dead();
 exit(0);
}

if(islocalhost()) exit(0);




# do_tcp = "no"; do_icmp = "no"; do_udp = "yes"; # TEST

###
if ("yes" >< do_arp && islocalnet() )
{
 # If the remote is on the local subnet and we are running over ethernet, and 
 # if arp fails, then arp_ping() will exit and mark the remote host as dead
 # (ie: it overrides the other tests)
 arp_ping();
}

if("yes" >< do_tcp)
{
 test = test + 1;
 p = script_get_preference("TCP ping destination port(s) :");
 if (!p) p = defportlist;
 if (p == "extended")
    p = "22;80;139;443;445;21;23;25;53;79;110;113;135;143;264;389;993;1454;1723;3389;8080;2869";

 #debug_print("TCP ports=",p,"\n");
 if(p != "built-in")
 {
  dport = ereg_replace(string:p, pattern:"([^;]*);(.*)", replace:"\1");
  while (dport)
  {
   p = p - dport;
   p = p - ";";
   # display(string("Port=",dport,"\n"));
   t1 = gettimeofday();
   if(tcp_ping(port:dport)){
        t2 = gettimeofday();
	#debug_print('Host answered to TCP SYN on port ', dport, '\n');
	log_live(rtt: difftime(t1: t1, t2: t2));
 	}
   dport = ereg_replace(string:p, pattern:"([^;]*);(.*)", replace:"\1");
  }
 }
 else
 {
  t1 = gettimeofday();
  if(tcp_ping())
  {
   t2 = gettimeofday();
   #debug_print('Host answered to TCP SYN (built-in port list)\n');
   log_live(rtt: difftime(t1: t1, t2: t2));
  }
 }
}

####

if ("yes" >< do_icmp)
{
src = this_host();
dst = get_host_ip();
retry = script_get_preference("Number of retries (ICMP) :");
retry = int(retry);
alive = 0;
if(retry <= 0) retry = 6;	# default

  #debug_print("ICMP retry count=", retry, "\n");
  j = 0;
  test = test + 1;
  filter = string("ip and src host ", get_host_ip());
  while(j < retry)
  {
   # MA 2002-02-01: we increment the IP ID. Keeping the same one is not
   # safe.
   id = 1235 +j;
   ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:0,ip_len:20,
 		        ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
		        ip_src:this_host());
   icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
  			    icmp_seq: 1, icmp_id:1);
   # MA: I planned to add a payload to the packet, so that IDS could detect 
   # a Nessus ping. Renaud was afraid that this may break something.
   # I have to admit that even a bad script kiddy could edit the script
   # The trick was to add data:"Nessus is pinging this host",
   # or maybe just: data:"Nessus",

   t1 = gettimeofday();
   rep = send_packet(pcap_active:TRUE,
   		     pcap_filter:filter,
		     pcap_timeout:1,
		     icmp);
   if(rep){
        t2 = gettimeofday();
	#debug_print(get_host_ip(), ' answered to ICMP ping\n');
	set_kb_item(name: "/tmp/ping/ICMP", value: TRUE);
   	log_live(rtt: difftime(t1: t1, t2: t2));
	}
   j = j+1;
 }
}

####

if("yes" >< do_udp)
{
 test ++;
 n = 0;

 tid = raw_string(rand() % 256, rand() % 256);
 dstports[n] = 53;
 requests[n] = 
   strcat(	tid,
		'\x00\x00',		# Standard query (not recursive)
		'\x00\x01',		# 1 question
		'\x00\x00',		# 0 answer RR
		'\x00\x00',		# 0 authority RR
		'\x00\x00',		# 0 additional RR
		'\x03www', '\x07example', '\x03com', '\x00',
		'\x00\x01',		# Type A
		'\x00\x01'		# Classe IN
	);
 n ++;

 xid = raw_string(rand() % 256, rand() % 256, rand() % 256, rand() % 256);
 dstports[n] = 111;
 requests[n] = 
   strcat(	xid,			# XID
		'\x00\x00\x00\x00',	# Call
		'\x00\x00\x00\x02',	# RPC version = 2
		'\x00\x01\x86\xA0',	# Programm = portmapper (10000)
		'\x00\x00\x00\x02',	# Program version = 2
		'\x00\x00\x00\x03',	# Procedure = GETPORT(3)
		'\0\0\0\0\0\0\0\0',	# Null credential
		'\0\0\0\0\0\0\0\0',	# Null verifier
		'\x00\x00\x27\x10',	# programm 10000
		'\x00\x00\x00\x02',	# version 2
		'\x00\x00\x00\x11',	# UDP = 17
		'\x00\x00\x00\x00'	# port
	);
 n ++;

 # RIP v1 & v2 - some buggy agents answer only on requests coming from 
 # port 520, other agents ignore such requests. So I did a mix: v1 with
 # privileged source port, v2 without. 
 for (v = 2; v >= 1; v --)
 {
  if (v == 1) srcports[n] = 520;
  dstports[n] = 520;
  requests[n] = raw_string(1, v, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 16);
  n ++;
 }

 srcports[n] = 123;	# Or any client port
 dstports[n] = 123;
 requests[n] = '\xe3\x00\x04\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC6\x34\xFF\xE6\x4B\xAE\xAB\x79';
 n ++;

#

 #debug_print('sending ', n, ' UDP requests\n');

 for (j = 0; j < n; j ++)
 {
  if (srcports[j]) sport = srcports[j];
  else sport = rand() % 64512 + 1024;
  ip = forge_ip_packet(ip_v: 4, ip_hl: 5, ip_tos: 0, # Should we try TOS=16?
	ip_ttl: 0x40, ip_p: IPPROTO_UDP, 
	ip_src: this_host(), ip_dst: get_host_ip());
  udp = forge_udp_packet(ip: ip, uh_sport: sport, uh_dport: dstports[j],
	data: requests[j]);
  # No need to filter source & destination port: if we get a UDP packet, the
  # host is alive. But we do not listen for any packet, in case there is a
  # broken filter or IPS that sends fake RST, for example.
  filter = "src host " + get_host_ip() + " and dst host " + this_host() + 
	" and (udp or (icmp and icmp[0]=3 and icmp[1]=3))";
  for (i = 0; i < 3; i ++)	# Try 3 times
  {
   t1 = gettimeofday();
   r = send_packet(udp, pcap_filter: filter, pcap_active: TRUE, pcap_timeout:1);
   if (r)
   {
    t2 = gettimeofday();
    ipp = get_ip_element(ip: r, element: 'ip_p');
    #debug_print('Host answered to UDP request on port ', dstports[j], ' (protocol=', ipp, ')\n');
    if (ipp == 17)
    {
     udpp = get_udp_element(udp: r, element: 'uh_sport');
     set_kb_item(name: '/tmp/ping/UDP', value: udpp);
     #if (udpp != dstports[j])
      #debug_print('Host sent an UDP packet from port ', udpp);
    }
    log_live(rtt: difftime(t1: t1, t2: t2));
   }
  }
 }
 ports = NULL; requests = NULL;
}

####

if( test != 0 ) log_dead();
