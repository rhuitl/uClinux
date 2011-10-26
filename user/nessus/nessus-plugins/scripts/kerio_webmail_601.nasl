#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14279);
 script_bugtraq_id(10936);
 script_version ("$Revision: 1.5 $");

 name["english"] = "Kerio MailServer < 6.0.1";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Kerio MailServer prior to 6.0.1.
Kerio Mailserver is an SMTP server which ships with an embedded HTTP server.

It has been reported that there are multiple remote overflows in
versions of Kerio prior to 6.0.1, although the exact nature of these
overflows is not yet known.

*** NOTE: Nessus determined this vulnerability based on the received
*** banner information from the host.  If the host is running 
*** obfuscated banners, this may be a false positive.

Solution : Upgrade to Kerio MailServer 6.0.1 or newer

See also : http://www.securityfocus.com/bid/10936/

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Kerio MailServer < 6.0.1";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_require_ports("Services/smtp", 25, "Services/www", 80);
 script_dependencies("http_version.nasl");
 exit(0);
}

include("smtp_func.inc");
include("http_func.inc");
include("http_keepalive.inc");


#
# SMTP hardcoded to 25
#
port = 25;
if(get_port_state(port))
{
	s = get_smtp_banner(port:port);
	# 220 f00dikator Kerio MailServer 6.0.1 ESMTP ready

	if (egrep(string:s, pattern:"^220 .* Kerio MailServer ([0-5]\.[0-9]\.[0-9]|6\.0\.0) ESMTP ready") )
	{
		security_hole(port);
		exit(0);
	}
}


# Now, let's try it via port 80

port = get_http_port(default:80);
if ( ! port || ! get_port_state(port) ) exit(0);
r = get_http_banner(port:port);
if ( ! r ) exit(0);
#Server: Kerio MailServer 6.0.1
if (egrep(string:r, pattern:"^Server: Kerio MailServer ([0-5]\.[0-9]\.[0-9]|6\.0\.0)") )
	security_hole(port);
