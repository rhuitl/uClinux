#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Nick Gudov <cipher@s-quadra.com>
#
# This script is released under the GNU GPL v2

if(description)
{
  script_id(15461);
  script_cve_id("CVE-2004-1881", "CVE-2004-1882");
  script_bugtraq_id(10019, 10020);
  if ( defined_func("script_xref") ) 
  {
    script_xref(name:"OSVDB", value:4785);
    script_xref(name:"OSVDB", value:4786);
    script_xref(name:"OSVDB", value:4787);
  }
  script_version("$Revision: 1.3 $");
  
  script_name(english:"CactuShop XSS and SQL injection flaws");

 
 desc["english"] = "
The remote host runs CactuShop, an e-commerce web application written in ASP.

The remote version of this software is vulnerable to cross-site scripting 
due to a lack of sanitization of user-supplied data in the script 
'popuplargeimage.asp'.

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server. 

This version may also be vulnerable to SQL injection attacks in 
the scripts 'mailorder.asp' and 'payonline.asp'. The user-supplied 
input parameter 'strItems' is not filtered before being used in 
an SQL query. Thus the query modification through malformed input 
is possible.

Successful exploitation of this vulnerability can enable an attacker
to execute commands in the system (via MS SQL the function xp_cmdshell).

Solution: Upgrade to the latest version of this software
Risk factor : High";

  script_description(english:desc["english"]);
  script_summary(english:"Checks CactuShop flaws");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/popuplargeimage.asp?strImageTag=<script>foo</script> ", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if(egrep(pattern:"<script>foo</script>", string:r))
{
  security_warning(port);
  exit(0);
}
