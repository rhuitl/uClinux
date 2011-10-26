#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2
# Ref: Erik Sjölund
# 

if(description)
{
 script_id(16387);
 script_bugtraq_id(12527);
 script_cve_id("CVE-2005-0073");
 name["english"] = "Sympa queue utility privilege escalation vulnerability";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.5 $"); 
 desc["english"] = "
The remote host seems to be running sympa, an open source mailing list 
management software.

The remote version of this software contains a vulnerability which can be 
exploited by malicious local user to gain escalated privileges.

This issue is caused due to a boundary error in the queue utility when 
processing command line arguments. This can cause a stack based buffer 
overflow.

Solution : Update to Sympa version 4.1.3 or newer
See also: http://www.sympa.org/
Risk factor : Medium";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for sympa version";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# the code
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


function check(url)
{
req = http_get(item:string(url, "home"), port:port);
r = http_keepalive_send_recv(port:port, data:req);
if ( r == NULL ) exit(0);

	if ("http://www.sympa.org/" >< r)
	{
        	if(egrep(pattern:".*ALT=.Sympa (2\.|3\.|4\.0|4\.1\.[012][^0-9])", string:r))
 		{
 			security_warning(port);
			exit(0);
		}
	}
}


foreach dir (cgi_dirs())
{
 check(url:dir);
}
