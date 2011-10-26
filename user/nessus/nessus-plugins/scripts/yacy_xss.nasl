#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Donato Ferrante <fdonato@autistici.org>
#
# This script is released under the GNU GPL v2

if(description)
{
  script_id(16058);

  script_cve_id("CVE-2004-2651");
  script_bugtraq_id(12104);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"12630");
  }
  script_version("$Revision: 1.5 $");
  
  script_name(english:"YaCy Peer-To-Peer Search Engine XSS");

 desc["english"] = "
Synopsis :

The remote host contains a peer-to-peer search engine that is prone to
cross-site scripting attacks. 

Description :

The remote host runs YaCy, a peer-to-peer distributed web search
engine and caching web proxy. 

The remote version of this software is vulnerable to multiple
cross-site scripting due to a lack of sanitization of user-supplied
data. 

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user. 

See also :

http://www.securityfocus.com/archive/1/385453

Solution: 

Upgrade to YaCy 0.32 or later.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";

  script_description(english:desc["english"]);
  script_summary(english:"Checks for YaCy Peer-To-Peer Search Engine XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 8080);
  script_dependencie("cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if ( ! get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/index.html?urlmaskfilter=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if(egrep(pattern:"<title>YaCy.+ Search Page</title>.*<script>foo</script>", string:r))
{
  security_note(port);
  exit(0);
}
