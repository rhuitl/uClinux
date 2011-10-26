#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10372);
 script_version ("$Revision: 1.16 $");

 name["english"] = "/scripts/repost.asp";
 script_name(english:name["english"]);
 
 desc["english"] = "
The file /scripts/repost.asp is present.

This file allows users to upload files to the /users directory if it has not 
been configured properly.

Solution : Create /users and make sure that the anonymous internet account is
only given read access to it.
See also : http://online.securityfocus.com/archive/82/84565
Risk factor : High";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines whether /scripts/repost.asp is present";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

function test_cgi(port, cgi, output)
{
 req = http_get(item:cgi, port:port);
 soc = http_open_socket(port);
 if(!soc)return(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 if(output >< r)
  {
  	security_hole(port);
	exit(0);
  }
 return(0);
}
 
 


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

test_cgi(port:port, cgi:"/scripts/repost.asp", output:"Here is your upload status");	  
