#
# (C) Michel Arboi 2002
#
# GNU Public Licence
#
# References
# Date: Thu, 24 Oct 2002 10:41:48 -0700 (PDT)
# From:"Jeremy C. Reed" <reed@reedmedia.net> 
# To:bugtraq@securityfocus.com
# Subject: Re: vpopmail CGIapps vpasswd vulnerabilities
# In-Reply-To: <200210241126.33510.n.bugtraq@icana.org.ar>
# Message-ID: <Pine.LNX.4.43.0210241020040.25224-100000@pilchuck.reedmedia.net>
#

if(description)
{
 script_id(11165);
 script_bugtraq_id(6038);
 
 script_version ("$Revision: 1.7 $");
 name["english"] = "vpasswd.cgi";
 script_name(english:name["english"]);
 
 desc["english"] = "The 'vpasswd.cgi' CGI is installed. Some versions
do not properly check for special characters and allow
a cracker to execute any command on your system.

*** Warning : Nessus solely relied on the presence of this CGI, it did not
*** determine if you specific version is vulnerable to that problem

Solution : remove it from /cgi-bin.

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of vpasswd.cgi";
 summary["francais"] = "Vérifie la présence de vpasswd.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"vpasswd.cgi", port:port);
if(res)security_warning(port);
