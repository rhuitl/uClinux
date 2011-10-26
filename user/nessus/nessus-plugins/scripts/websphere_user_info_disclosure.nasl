#
# (C) Tenable Network Security
#

if(description)
{
  script_id(16173);
  script_version ("$Revision: 1.2 $");
  script_bugtraq_id(11816);
  name["english"] = "IBM Websphere default user information leak";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote web server is affected by an information disclosure issue. 

Description :

The remote host is running a version of IBM Websphere Commerce that
may allow potentially confidential information to be accessed through
the default user account.  An attacker, exploiting this flaw, would
only need to be able to make standard queries to the application
server. 

See also :

http://publib.boulder.ibm.com/infocenter/wc56help/index.jsp?topic=/com.ibm.commerce.esupport.doc/html/Security/swg21187876.html

Solution : 

Contact WebSphere Commerce support to resolve the issue. 

Risk: 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";


  script_description(english:desc["english"]);
  summary["english"] = "Detects Websphere default user information leak";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}



include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
	banner = get_http_banner(port: port);
	if(!banner)
		exit(0);
	# Server: WebSphere Application Server/6.0
	if (egrep(string:banner, pattern:"^Server: WebSphere Application Server/([0-4]\.|5\.[0-6][^0-9])"))	
		security_note(port);
}



