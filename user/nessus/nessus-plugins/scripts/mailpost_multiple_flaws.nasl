#
# (C) Tenable Network Security
# 


if(description)
{
 script_id(15626);
 script_version ("$Revision: 1.4 $");

 script_cve_id("CVE-2004-1102");
 script_bugtraq_id(11595, 11596, 11598, 11599);
 script_xref(name:"OSVDB", value:"11410");

 name["english"] = "TIPS MailPost Multiple Flaws";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version of TIPS MailPost which is vulnerable
to several flaws.

TIPS MailPost is an HTML form content email application designed to facilitate
the emailing of HTML form data to a third party.

There are various flaws in the remote version of this software :

- A remote file enumeration vulnerability which may allow an attacker to 
determine if a file exists or not

- Two cross site scripting vulnerabilities which may allow an attacker to steal
the cookies of third-parties users 

- An information disclosure vulnerability which may allow an attacker to gain
more information about the remote host  

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Test the remote mailpost.exe";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

########


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

foreach dir (cgi_dirs())
{
 res = http_keepalive_send_recv(port:port, data:http_get(port:port, item:dir + "/mailpost.exe?<script>foo</script>"));
 if ( res == NULL ) exit(0);
 if ( "CGI_QueryString= <script>foo</script>" >< res ) {
	security_warning(port);
	exit(0);
	}
}

