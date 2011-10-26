#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11197);
 script_bugtraq_id(6535);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2003-0001");
 
 

 
 name["english"] = "Etherleak";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host leaks memory in network packets.

Description :

The remote host is vulnerable to an 'Etherleak' - the remote
ethernet driver seems to leak bits of the content of the memory
of the remote operating system.

Note that an attacker may take advantage of this flaw only when
its target is on the same physical subnet.

See also :

http://www.atstake.com/research/advisories/2003/a010603-1.txt 

Solution :

Contact your vendor for a fix

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "etherleak check";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#
##include("dump.inc");

if ( ! islocalnet() ) exit(0);

function probe()
{
 ip     = forge_ip_packet(ip_p:IPPROTO_ICMP, ip_src:this_host());
 icmp   = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:1, icmp_id:1, data:"x");

 filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host());

 for(i=0;i<3;i++)
 {
 rep = send_packet(icmp, pcap_filter:filter);
 if(rep)break;
 }

 if(rep == NULL)exit(0);
##dump(dtitle: "ICMP", ddata: rep);

 len = get_ip_element(ip:rep, element:"ip_len");
 if(strlen(rep) > len)
 {
 str="";
 for(i=len;i<strlen(rep);i++)
  {
   str = string(str, rep[i]);
  }
  return(str);
 }
 else return(NULL);
}

function ping()
{
 ip     = forge_ip_packet(ip_p:IPPROTO_ICMP, ip_src:this_host());
 icmp   = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:1, icmp_id:1, data:crap(data:"nessus", length:254));

 filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host());

 for(i=0;i<3;i++) rep = send_packet(icmp, pcap_filter:filter, pcap_timeout:1);
}

if(islocalhost())exit(0);


if(islocalnet())
{
 str1 = probe();
 ping();
 sleep(1);
 str2 = probe();

##dump(dtitle: "ether1", ddata: str1);
##dump(dtitle: "ether2", ddata: str2);

 if(isnull(str1) || isnull(str2))exit(0);

 if( str1 != str2 ){
		security_note(proto:"icmp", port:0);
		set_kb_item(name:"Host/etherleak", value:TRUE);
	}
}
