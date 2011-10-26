# This script was written by Michel Arboi <mikhail@nessus.org>
# 
# See:
# http://www.simovits.com/trojans/tr_data/y2814.html
# http://www.bizsystems.com/downloads/labrea/localTrojans.pl

if(description)
{
 script_id(18164);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Port TCP:0";
 script_name(english:name["english"]);
 
 desc["english"] = "
TCP port 0 is open on the remote host.
This is highly suspicious as this TCP port is reserved
and should not be used. This might be a backdoor (REx).

Solution : Check your system
Risk factor : High";


 script_description(english:desc["english"]);


 summary["english"] = "Open a TCP connection to port 0";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");

 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 exit(0);
}

# I'm not sure this works with any OS, so I wrote a pcap version
# s = open_sock_tcp(0);
# if (s) 
# {
#  security_warning(port: 0);	# Nessus API cannot really handle this
#  close(s);
# }

if ( islocalhost() ) exit(0);

saddr = this_host();
daddr = get_host_ip();
sport = rand() % 64512 + 1024;
dport = 0;
filter = strcat('src port ', dport, ' and src host ', daddr, 
	' and dst port ', sport, ' and dst host ', saddr);

ip = forge_ip_packet(	ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
			ip_p:IPPROTO_TCP, ip_ttl:0x40,
			ip_src: saddr);
tcp = forge_tcp_packet( ip: ip, th_sport: sport, th_dport: dport,
                          th_flags: TH_SYN, th_seq: rand(), th_ack: 0,
                          th_x2: 0, th_off: 5, th_win: 512, th_urp:0);

for (i = 0; i < 3; i ++)
{
  reply =  send_packet(pcap_active : TRUE, pcap_filter : filter,
                        pcap_timeout:2, tcp);
  if (reply)
  {
    flags = get_tcp_element(tcp: reply, element: "th_flags");
    if ((flags & TH_SYN) && (flags & TH_ACK))
      security_warning(port: 0); # Nessus API cannot really handle this
    exit(0);
  }
}

