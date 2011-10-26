#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref: Paul Johnson <baloo at ursine dot dyndns dot org>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14298);
 script_version ("$Revision: 1.8 $");
 #script_cve_id("CVE-MAP-NOMATCH");
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8690");
 name["english"] = "Sympa wwsympa do_search_list Overflow DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running SYMPA, an open source mailing list software.

This version of Sympa has a flaw in one of it's scripts (wwsympa.pl) which
would allow a remote attacker to overflow the sympa server.  Specifically,
within the cgi script wwsympa.pl is a do_search_list function which fails to perform
bounds checking.  An attacker, passing a specially formatted long string
to this function, would be able to crash the remote sympa server.  At the
time of this writing, the attack is only known to cause a Denial of Service
(DoS).

Solution : Update to version 4.1.2 or newer

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

if(!get_port_state(port))
	exit(0);


function check(url)
{
	req = http_get(item:string(url, "home"), port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if ( r == NULL ) 
		exit(0);

	if ("www.sympa.org" >< r)
	{
		# jwl : thru 3.3.5.1 vuln
        	if(egrep(pattern:"www\.sympa\.org.*ALT=.Sympa ([0-2]\.|3\.[0-2]|3\.3\.[0-4]|3\.3\.5\.[01])([^0-9]|$)", string:r))
 		{
 			security_warning(port);
			exit(0);
		}
	}
 
}

check(url:"");
check(url:"/wws/");
check(url:"/wwsympa/");

foreach dir (cgi_dirs())
{
 check(url:dir);
}
