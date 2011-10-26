#
# This script was entirely rewritten by Michel Arboi <mikhail@.nessus.org>
#
# GNU Public License
#

if(description)
{
 script_id(10049);
 script_bugtraq_id(128);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-0021");
 name["english"] = "Count.cgi";
 script_name(english:name["english"]);
 
 desc["english"] = "
An old version of 'Count.cgi' cgi is installed. 
It has a well known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root, nobody, www...)

** Note that Nessus only checked the version number 

Solution : upgrade to wwwcount 2.4 or later.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks Count.cgi version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", 
	"DDI_Directory_Scanner.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

foreach d (cgi_dirs())
{
  req = http_get(port: port, item: strcat(d, "/Count.cgi?align=topcenter"));
  r = http_keepalive_send_recv(port: port, data: req);
  r = strstr(r, "Count.cgi ");
  if (r && ereg(string:r, pattern:".*Count\.cgi +([01]\.[0-9]+|2\.[0-3]+)"))
  {
    security_hole(port);
    exit(0);
  }
}
