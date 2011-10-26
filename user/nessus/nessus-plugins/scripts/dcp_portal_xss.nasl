#
#  Written by K-Otik.com <ReYn0@k-otik.com>
#
#  DCP-Portal Cross Site Scripting Bugs
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#
#  Modified by David Maciejak <david dot maciejak at kyxar dot fr>
#  add ref:  Alexander Antipov <antipov@SecurityLab.ru>

if (description)
{
 script_id(11446);
 script_cve_id("CVE-2004-2511", "CVE-2004-2512");
 script_bugtraq_id(7141, 7144, 11338, 11339, 11340);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"10585");
   script_xref(name:"OSVDB", value:"10586");
   script_xref(name:"OSVDB", value:"10587");
   script_xref(name:"OSVDB", value:"10588");
   script_xref(name:"OSVDB", value:"10589");
   script_xref(name:"OSVDB", value:"10590");
   script_xref(name:"OSVDB", value:"11405");
 }
 script_version ("$Revision: 1.15 $");

 script_name(english:"DCP-Portal XSS");
 desc["english"] = "
You are running a version of DCP-Portal which is older or equals to v5.3.2

This version is vulnerable to:

- Cross-site scripting flaws in calendar.php script, which may let an
attacker to execute arbitrary code in the browser of a legitimate user.

In addition to this, your version may also be vulnerable to:

- HTML injection flaws, which may let an attacker to inject hostile
HTML and script code that could permit cookie-based credentials to be stolen
and other attacks.

- HTTP response splitting flaw, which may let an attacker to influence 
or misrepresent how web content is served, cached or interpreted.

See also : http://archives.neohapsis.com/archives/bugtraq/2004-10/0042.html
           http://archives.neohapsis.com/archives/fulldisclosure/2004-10/0131.html

Solution : Upgrade to a newer version when available
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Check for DCP-Portal XSS flaws");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 k-otik.com & Copyright (C) 2004 David Maciejak");
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/calendar.php?year=2004&month=<script>foo</script>&day=01");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
 if( "<script>foo</script>" >< buf )
   {
    security_warning(port);
    exit(0);
   }
}

