# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# References:
#
# http://cert.uni-stuttgart.de/archive/bugtraq/2001/10/msg00082.html
#
# Date:  Sun, 10 Mar 2002 21:37:33 +0100
# From: "Obscure" <obscure@eyeonsecurity.net>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: IMail Account hijack through the Web Interface
#
#  Date:  Mon, 11 Mar 2002 04:11:43 +0000 (GMT)
# From: "Zillion" <zillion@safemode.org>
# To: "Obscure" <obscure@zero6.net>
# CC: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org, "Obscure" <obscure@eyeonsecurity.net>
# Subject: Re: IMail Account hijack through the Web Interface
#


if(description)
{
 script_id(11271);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "IMail account hijack";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running IMail web interface.
In this version, the session is maintained via the URL. It 
will be disclosed in the Referer field if you receive an
email with external links (e.g. images)

Solution : Upgrade to IMail 7.06
 or turn off the 'ignore source address in security check' option.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of IMail web interface";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"Copyright (C) 2003 Michel Arboi");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 #script_require_keys("www/IMail");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include ("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

banner = get_http_banner(port: port);
serv = egrep(string: banner, pattern: "^Server:.*");
if(ereg(pattern:"^Server:.*Ipswitch-IMail/(([1-6]\.)|(7\.0[0-5]))", string:serv))
   security_warning(port);

