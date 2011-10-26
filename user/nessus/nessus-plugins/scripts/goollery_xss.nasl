#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: Lostmon <lostmon@gmail.com>
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(15717);
 script_cve_id("CVE-2004-2245");
 script_bugtraq_id(11587);
 if ( defined_func("script_xref") ) {
   script_xref(name:"OSVDB", value:"11318");
   script_xref(name:"OSVDB", value:"11319");
   script_xref(name:"OSVDB", value:"11320");
   script_xref(name:"OSVDB", value:"11624");
 }
 
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Goollery Multiple XSS";
 script_name(english:name["english"]);
 desc["english"] = "
Goollery, a GMail based photo gallery written in PHP, 
is installed on this remote host.

According to it's version number, this host is vulnerable to multiple
cross-site-scripting (XSS) attacks; eg, through the 'viewpic.php'
script.  An attacker, exploiting these flaws, would need to be able to
coerce a user to browse a malicious URI.  Upon successful exploitation,
the attacker would be able to run code within the web-browser in the
security context of the remote server. 

Solution : Upgrade to Goollery 0.04b or newer.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Goollery XSS flaw in viewpic.php ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
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
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

function check(loc)
{
 	req = http_get(item:string(loc, "/viewpic.php?id=7&conversation_id=<script>foo</script>&btopage=0"),
 		port:port);			
 	r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 	if( r == NULL )
		exit(0);
 	if(egrep(pattern:"<script>foo</script>", string:r))
 	{
 		security_warning(port);
		exit(0);
 	}
}

dir = make_list(cgi_dirs(),"/goollery");
foreach d (dir)	
{
 	check(loc:d);
}
