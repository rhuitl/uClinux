#
# Written by Renaud Deraison
#
#
# See the Nessus Scripts License for details
#
# Ref:
# From: Martin Eiszner <martin@websec.org>
# To: bugtraq@securityfocus.com
# Subject: axis2400 webcams
# Message-Id: <20030228104612.7f035235.martin@websec.org>
#
#
# Thanks to Martin for having sent me a sample output of /support/messages :
#
# Jan 20 15:19:04 AxisProduct camd[22]: CGI syntax error 13163 str=HTTP/1.0 400
# 



if(description)
{
 script_id(11298);
 script_bugtraq_id(6980, 6987);

 
 script_version ("$Revision: 1.7 $");
 name["english"] = "axis2400 webcams";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Axis product is vulnerable to several
flaws, including :
 - Information disclosure (an attacker may view the remote
   /var/log/messages file)
 - Overwriting of system files
 - Arbitrary file creation
 
An attacker may use these flaws to prevent this product from 
working properly or to gather information to make a better
attack against the rest of your network.

Solution : Contact your vendor for a patch
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "reads the remote /var/log/messages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "os_fingerprint.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

os = get_kb_item("Host/OS/icmp");
if ( os && "Axis" >!< os ) exit(0);

port = get_http_port(default:80);
req = http_get(item:"/support/messages", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);
if(egrep(pattern:"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]*.*AxisProduct .*", string:res))
	security_hole(port);
