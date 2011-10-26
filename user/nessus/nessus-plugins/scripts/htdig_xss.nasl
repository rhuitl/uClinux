#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Howard Yeend <h_bugtraq@yahoo.com>
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(15706);
 script_cve_id("CVE-2002-2010");
 script_bugtraq_id(5091);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"7590");
 
 script_version ("$Revision: 1.5 $");
 name["english"] = "ht://Dig htsearch.cgi XSS";
 script_name(english:name["english"]);
 
 desc["english"] = 
"The 'htsearch' CGI, which is part of the ht://Dig package, 
is vulnerable to cross-site scripting attacks,
throught 'words' variable.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity.

Solution : Upgrade to a newer when available
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if ht://Dig is vulnerable to XSS flaw in htsearch.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
  script_dependencie("cross_site_scripting.nasl");
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
if ( ! port ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
   foreach dir (cgi_dirs())
   {
  	buf = http_get(item:string(dir,"/htsearch.cgi?words=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E"), port:port);
  	r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  	if( r == NULL )exit(0);
  	if(egrep(pattern:"<script>foo</script>", string:r))
  	{
    		security_warning(port);
	 	exit(0);
  	}
   }
}
