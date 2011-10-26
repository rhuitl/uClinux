#
# (C) Tenable Network Security
#

if(description)
{
  script_id(17193);
  script_bugtraq_id(12620);
  script_version("$Revision: 1.2 $");
  
  script_name(english:"Bizmail.cgi Mail From Unauthorized Mail Relay Vulnerability");

 desc["english"] = "
The remote web server is hosting the CGI bizmail.cgi, a CGI application
which sends web forms to email addresses.

The remote version of this software is vulnerable to a flaw which may
allow an attacker to use the remote CGI as a mail relay.

A spammer may exploit this flaw to send emails anonymously.

Solution: Upgrade to Bizmail 2.2 or newer
Risk factor : High";

  script_description(english:desc["english"]);
  script_summary(english:"Checks the version of bizmail.cgi");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item: dir + "/bizmail.cgi", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( "Biz Mail Form " >< res )
 {
  if ( egrep(pattern:"Biz Mail Form.* ([01]\.|2\.[01] )", string:res) )
	{
	security_hole ( port );
	exit(0);
	}
 }
}
