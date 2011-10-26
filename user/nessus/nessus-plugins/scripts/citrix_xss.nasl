#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Eric Detoisien <eric.detoisien@global-secure.fr>.
#
# This script is released under the GNU GPLv2


if(description)
{
 script_id(14626);
 script_bugtraq_id(4372);
 script_cve_id("CVE-2002-0504");
 if ( defined_func("script_xref")) script_xref(name:"OSVDB", value:"9256");
 if ( defined_func("script_xref")) script_xref(name:"OSVDB", value:"9257");
  
 script_version("$Revision: 1.9 $");
 
 name["english"] = "Citrix NFuse_Application parameter XSS";
 script_name(english:name["english"]);

 desc["english"] = "
The remote Citrix NFuse contains a flaw that allows a remote cross site 
scripting attack.

With a specially crafted request, an attacker can cause arbitrary code 
execution resulting in a loss of integrity.

Risk Factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Test Citrix NFuse_Application parameter XSS";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# start the test

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


scripts = make_list("/launch.jsp", "/launch.asp");

found =  NULL;

foreach script (scripts)
{
 req = http_get(item:string(script,"?NFuse_Application=>alert(document.cookie);</script>"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if("400 - Bad Request" >!< r && "alert(document.cookie);</script>" >< r )
 {
       security_hole(port);
       exit(0);
 }
}

