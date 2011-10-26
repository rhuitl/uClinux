#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(12093);
 script_cve_id("CVE-2004-1809");
 script_bugtraq_id(9865, 9866);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"4257");
   script_xref(name:"OSVDB", value:"4259");
 }
 
 script_version("$Revision: 1.10 $");
 name["english"] = "phpBB Cross-Site scripting vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a cross site scripting vulnerability in the files
'ViewTopic.php' and 'ViewForum.php' in the remote installation of
phpBB. 

Solution : Upgrade to the latest version of this software.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "XSS test";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("phpbb_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
dir = matches[2];


req = http_get(item:dir + "/viewtopic.php?t=10&postdays=99<script>foo</script>", port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if(buf == NULL)exit(0);
req = http_get(item:dir + "/viewforum.php?f=10&postdays=99<script>foo</script>", port:port);
buf2 = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if(buf2 == NULL)exit(0);

if("<script>foo</script>" >< buf || "<script>foo</script>" >< buf2 )
	security_warning(port);
