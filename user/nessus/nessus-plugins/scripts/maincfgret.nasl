#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(15564);
 script_bugtraq_id ( 11043 );
 script_cve_id("CVE-2004-0798");
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Whatsup Gold vulnerable CGI";
 script_name(english:name["english"]);
 
 desc["english"] = "The '_maincfgret' cgi is installed. 
Some versions were vulnerable to a buffer overflow.

** This might be a false positive, no attack was performed
** and the version was not checked

http://www.idefense.com/application/poi/display?id=142&type=vulnerabilities
http://www.packetstormsecurity.org/0408-advisories/08.25.04.txt

Solution : upgrade to Whatsup Gold 8.03 HF 1 if needed

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /_maincfgret.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if (is_cgi_installed_ka(item: "/_maincfgret.cgi", port:port))
{
  security_warning(port);
  exit(0);
}

if (is_cgi_installed_ka(item:"_maincfgret.cgi", port:port)) 
 security_warning(port);
