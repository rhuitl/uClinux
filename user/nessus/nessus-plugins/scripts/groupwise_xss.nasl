#
# (C) Tenable Network Security
#

if(description)
{
  script_id(16174);
  script_bugtraq_id(12310);
  script_version("$Revision: 1.4 $");
  
  script_name(english:"Novell GroupWise WebAccess XSS");

 desc["english"] = "
The remote host is running Novell GroupWise WebAccess, a commercial
commercial groupware package.

The remote version of this software is vulnerable to multiple cross-site 
scripting due to a lack of sanitization of user-supplied data.

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user.

Solution: Upgrade to the latest version of this software
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks GroupWare XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_dependencie("cross_site_scripting.nasl");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/servlet/webacc?User.lang=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if("/com/novell/webaccess/images/btnlogin<script>foo</script>.gif" >< r )
{
  security_warning(port);
  exit(0);
}
