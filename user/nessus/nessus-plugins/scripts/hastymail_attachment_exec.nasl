#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14370);
 script_bugtraq_id(11022);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "HastyMail HTML Attachement Script Execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running HastyMail, a PHP-based mail client application.

There is a flaw in the remote version of this software which may allow
an attacker to execute arbitrary javascript code on the hosts of users
of this software.

To exploit this flaw, an attacker would need to send an email to a victim
using HastyMail containing a malicious HTML attachment. When the victim attempts
to read the attachment, his browser may attempt to render the HTML file.

An attacker may use this flaw to steal the cookies of the victim and 
therefore get access to his mailbox, or may perform other attacks.

Solution : Upgrade to HastyMail 1.0.2 or 1.2.0
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of HastyMail";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/login.php"), port:port);

 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if("Hastymail" >< r && egrep(pattern:"Hastymail (0\.|1\.0\.[01]|1\.1\.)", string:r) )
 {
 	security_warning(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

