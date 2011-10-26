#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14186);
 script_cve_id("CVE-2004-2528");
 script_bugtraq_id(10837);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8260");
 }
 script_version ("$Revision: 1.4 $"); 
 name["english"] = "WebCam Watchdog sresult.exe XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running WebCamSoft's watchdog software. There is a
CGI included in this software suite ('sresult.exe') which is vulnerable
to a cross site scripting attack.

An attacker may use it to steal cookie-based credentials from a legitimate
user of this site.

See also : http://members.lycos.co.uk/r34ct/main/Webcam_watchdog_401a.txt
Solution : Upgrade to the newest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in watchdog";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#



include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);


foreach dir (cgi_dirs())
{
 req = http_get(item:"/sresult.exe?cam=<script>foo</script>", port:port);
 res = http_keepalive_send_recv(data:req, port:port, bodyonly:1); 
 if ( ! res ) exit(0);
 if ("<script>foo</script>" >< res )
 {
  security_warning(port);
  exit(0);
 }
}

