#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# References:
# Date:	 Fri, 05 Sep 2003 09:41:37 +0800
# From:	"pokleyzz" <pokleyzz@scan-associates.net>
# To:	bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: [SCAN Associates Sdn Bhd Security Advisory] Foxweb 2.5 bufferoverflow in CGI and ISAPI extension
#

if(description)
{
 script_id(11939);
 script_version ("$Revision: 1.7 $");
 name["english"] = "foxweb CGI";
 script_name(english:name["english"]);
 
desc["english"] = "
The foxweb.dll or foxweb.exe CGI is installed. 
 
Versions 2.5 and below of this CGI program have a security flaw 
that lets an attacker execute arbitrary code on the remote server.

** Since Nessus just verified the presence of the CGI but could
** not check the version number, this might be a false alarm.

Solution : remove it from /cgi-bin or upgrade it

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of foxweb.exe or foxweb.dll";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

l = make_list("foxweb.dll", "foxweb.exe");
foreach cgi (l)
{
  res = is_cgi_installed_ka(item:cgi, port:port);
  if(res)
  {
    security_hole(port);
    exit(0);	# As we might fork, we exit here
  }
}
