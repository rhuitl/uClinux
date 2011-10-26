#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10443);
 script_bugtraq_id(107, 10881, 670);
 script_cve_id("CVE-1999-0077");

 script_version ("$Revision: 1.14 $");
 
 name["english"] = "Predictable TCP sequence number";

 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has predictable TCP sequence numbers.

An attacker may use this flaw to establish spoofed TCP
connections to this host.

Solution : Contact your vendor for a patch
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "TCP SEQ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
		
		
 family["english"] = "General"; 
 script_family(english:family["english"], francais:family["francais"]);
 
 exit(0);
}

include('global_settings.inc');
if ( report_paranoia < 2 ) exit(0);

MAX_RETRIES = 5;

function probe(port)
{
 local_var sport, ip, tcp, filter, i, rep, seq;
 
 ip = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31338,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_TCP,
        ip_src  :this_host()
        );

  sport = (rand() % 60000) + 1024;
  
  tcp = forge_tcp_packet(ip:ip,
                               th_sport: sport,
                               th_dport: port,
                               th_flags:TH_SYN,
                               th_seq: rand(),
                               th_ack: 0,
                               th_x2: 0,
                               th_off: 5,
                               th_win: 8192,
                               th_urp: 0);
 filter = "tcp and src host " + get_host_ip() + " and src port " + port + " and dst port " + sport;
 for ( i = 0 ; i < MAX_RETRIES ; i ++ )
 {
   rep = send_packet(tcp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
   if ( rep ) break;
 }

 if ( ! rep ) 
	exit(0);
 
 flags = get_tcp_element(tcp:rep, element:"th_flags");
 if ( flags != (TH_SYN|TH_ACK)) 
	exit(0);
 seq = get_tcp_element(tcp:rep, element:"th_seq");
 return seq;
}


ports = get_kb_list("Ports/tcp/*");
if ( isnull(ports) ) 
	exit(0);
ports = keys(ports);

port = int( ports[0] - "Ports/tcp/" );
if ( ! port ) 
	exit(0);


for (mu=0; mu<5; mu++)
{

	seqs = make_list();
	for ( i = 0 ; i < 5 ; i ++ )
	{
 		seqs[i] = probe(port:port);
	}

	diffs = make_list();

	for ( i = 1; i < 5 ; i ++ )
	{
	 	diffs[i - 1] = seqs[i] - seqs[i - 1]; 
 		# Ugly hack, as NASL does not handle unsigned ints
 		if ( diffs[i - 1] < 0 ) 
			diffs[i - 1] *= -1;
	}

	a = diffs[0];

	for ( i = 1 ; i < 4 ; i ++ )
	{
 		b = diffs[i];
 		if ( a < b ) 
		{ 
			c = a; 
			a = b; 
			b = c;
		}
 		else 
		{
			while ( b) 
			{ 
				c = a % b; 
				a = b; 
				b = c; 
			}
		}
	}
	if (mu == 0)
	{
		results = make_list(a);
	}
	else
	{
		results = make_list(results, a);                       
	}
}

	
if ( (results[0] == results[1]) &&
	(results[0] == results[2]) &&
	(results[0] == results[3]) &&
	(results[0] == results[4]) ) 
		security_hole(0);


