#
# (C) Tenable Network Security
#


if (description)
{
 script_id(13843);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2004-0725", "CVE-2004-2233");
 script_bugtraq_id(10697, 10718, 10766);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"7710");
 }

 script_name(english:"Moodle < 1.3.3");
 desc["english"] = "
The remote host is running a version of the Moodle PHP suite which is
older than version 1.3.3.

The remote version of this software is vulnerable to a cross site scripting
issue in help.php, as well as to an undisclosed vulnerability in the language
settings management.

Solution : Upgrade to Moodle 1.3.3 or later.
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if Moodle is older than 1.3.3");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("moodle_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];
 req = http_get(item:string(dir, "/help.php?file=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(res == NULL ) exit(0);
 
 if( "Help file '<script>x</script>' could not be found!" >< res )
 {
    	security_warning(port);
	exit(0);
 }
}
