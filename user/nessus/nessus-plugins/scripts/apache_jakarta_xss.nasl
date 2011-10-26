#  
#  (C) Copyright: Tenable network Security
#  This script is written by shruti@tenablesecurity.com. 
#  based on work done by Renaud Deraison. 
#  Ref: Announced by vendor
#

if(description)
{
 script_id(15908);
 script_bugtraq_id( 11803 );
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"11704");
 script_version("$Revision: 1.5 $");
 
 name["english"] = "Apache Jakarta Cross-Site Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote Apache Jakarta Lucene software is vulnerable to a cross site
scripting issue.

Description :

The remote host is using Apache Jakarta Lucene, a full-featured text 
search engine library implemented in Java.

There is a cross site scripting vulnerability in the script 'results.jsp'
which may allow an attacker to steal the cookies of legitimate users on
the remote host.

Solution : 

Upgrade to Apache Software Foundation Jakarta Lucene 1.4.3

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks XSS in Apache Jakarta Lucene.";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit ( 0 );

function check_dir(path)
{
 req = http_get(item:string(path, '/results.jsp?query="><script>foo</script>"'), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);

 if ( "<script>foo</script>" >< res )
 {
  security_note(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check_dir(path:dir);
}
 
