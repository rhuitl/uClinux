#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# This script is released under the GNU GPLv2


if(description)
{
script_id(14299);
 
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8689");
 #script_bugtraq_id(?);
 #script_cve_id("CVE-MAP-NOMATCH");
 name["english"] = "Sympa invalid LDAP password DoS";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.9 $"); 
 desc["english"] = "
The remote host seems to be running sympa, an open source mailing list 
software.

This version of Sympa contains a flaw in the processing of LDAP 
passwords.  An attacker, exploiting this flaw, would need network
access to the webserver.  A successful attack would crash the sympa
application and render it useless.

Solution : Update to version 3.4.4.1 or newer

See also: http://www.sympa.org/

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for sympa version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(url)
{
req = http_get(item:string(url, "/home"), port:port);
r = http_keepalive_send_recv(port:port, data:req);
if ( r == NULL ) exit(0);

    #We need to match this
    
    #TD NOWRAP><I>Powered by</I></TD>
    #<TD><A HREF="http://www.sympa.org/">
    #       <IMG SRC="/icons/sympa/logo-s.png" ALT="Sympa 3.4.3" BORDER="0" >
	if ("http://www.sympa.org" >< r)
	{
        	if(egrep(pattern:".*ALT=.Sympa 3\.4\.3", string:r))
 		{
 			security_warning(port);
			exit(0);
		}
	}
 
}

check(url:"/wws");
check(url:"/wwsympa");

foreach dir (cgi_dirs())
{
 check(url:dir);
}
