#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10539);
 script_bugtraq_id(136, 678);
 script_cve_id("CVE-1999-0024");
 script_version ("$Revision: 1.22 $");
 name["english"] = "Usable remote name server";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote name server allows recursive queries to be performed
by the host running nessusd.


Description :

It is possible to query the remote name server for third party names.

If this is your internal nameserver, then forget this warning.

If you are probing a remote nameserver, then it allows anyone
to use it to resolve third parties names (such as www.nessus.org).
This allows hackers to do cache poisoning attacks against this
nameserver.

If the host allows these recursive queries via UDP,
then the host can be used to 'bounce' Denial of Service attacks
against another network or system.

See also : 

http://www.cert.org/advisories/CA-1997-22.html

Solution : 

Restrict recursive queries to the hosts that should
use this nameserver (such as those of the LAN connected to it).

If you are using bind 8, you can do this by using the instruction
'allow-recursion' in the 'options' section of your named.conf

If you are using bind 9, you can define a grouping of internal addresses
using the 'acl' command

Then, within the options block, you can explicitly state:
'allow-recursion { hosts_defined_in_acl }'

For more info on Bind 9 administration (to include recursion), see: 
http://www.nominum.com/content/documents/bind9arm.pdf

If you are using another name server, consult its documentation.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:N/I:P/B:I)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the remote name server allows recursive queries";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("smtp_settings.nasl", "dns_server.nasl");

 exit(0);
}

#
# We ask the nameserver to resolve www.<user_defined_domain>
#
include("dns_func.inc");
include("byte_func.inc");

if ( (!get_kb_item("Services/dns")) && (!get_kb_item("Services/udp/dns") )) exit(0);

host = "www";
domain = get_kb_item("Settings/third_party_domain");
if(!domain)domain = "nessus.org";

req =  host + "." + domain;
req = mk_query_txt(req);

req = mk_query(txt:req, type:0x0001, class:0x001);

dns["transaction_id"] = rand() % 65535; # Random
dns["flags"]  = 0x0100;	# Standard query, recursion desired
dns["q"]      = 1;	# 1 Q
dns["an_rr"]  = 0;
dns["au_rr"]  = 0;
dns["ad_rr"]  = 0;

req = mkdns(dns:dns, query:req);
soc = open_sock_udp(53);

send(socket:soc, data:req);
r  = recv(socket:soc, length:4096);
close(soc);
if ( ! r ) exit(0);

pk = dns_split(r);

if ( (pk["flags"] & 0x8085) == 0x8080 )
 security_warning(port:53, proto:"udp");
