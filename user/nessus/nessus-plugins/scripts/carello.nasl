#
# (C) Michel Arboi <arboi@alussinan.org>
#
#
# References:
#
# Date: Wed, 02 Oct 2002 17:10:21 +0100
# From: "Matt Moore" <matt@westpoint.ltd.uk>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: wp-02-0012: Carello 1.3 Remote File Execution (Updated 1/10/2002)
#
# http://www.westpoint.ltd.uk/advisories/wp-02-0012.txt
# 


if(description)
{
 script_id(11776);
 script_version ("$Revision: 1.5 $");

 name["english"] = "Carello detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
Carello.dll was found on your web server. 
Versions up to 1.3 of this web shopping cart allowed anybody
to run arbitrary commands on your server.

*** Note that no attack was performed, and the version number was
*** not checked, so this might be a false alert

Solution : Upgrade to the latest version if necessary
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of carello.dll";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# Please note that it is possible to test this vulnerability, but
# I suspect that Carello is not widely used, and I am lazy :-)
# 
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"Carello.dll", port:port);
if (res) security_warning(port);
