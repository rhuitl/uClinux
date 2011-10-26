# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# GPL
# References:
# Date:  Thu, 25 Oct 2001 12:21:37 -0700 (PDT)
# From: "MK Ultra" <mkultra@dqc.org>
# To: bugtraq@securityfocus.com
# Subject: Weak authentication in iBill's Password Management CGI

if(description)
{
 script_id(11083);
 script_cve_id("CVE-2001-0839");
 script_bugtraq_id(3476);
 script_version ("$Revision: 1.8 $");
  
 name["english"] = "ibillpm.pl";
 script_name(english:name["english"]);
 
 desc["english"] = "The 'ibillpm.pl' CGI is installed.
Some versions of this CGI use a weak password management system
that can be brute-forced.

** No flaw was tested. Your script might be a safe version.

Solutions : upgrade the script if possible. If not:
1) Move the script elsewhere (security through obscurity)
2) Request that iBill fix it.
3) Configure your web server so that only addreses from ibill.com
   may access it.

Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/ibillpm.pl";
 summary["francais"] = "Vérifie la présence de /cgi-bin/ibillpm.pl";

 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 family["deutsch"] = "CGI Mißbrauch";
 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"ibillpm.pl", port:port);
if(res)security_warning(port);
# Note: we could try to access it. If we get a 403 the site is safe.
