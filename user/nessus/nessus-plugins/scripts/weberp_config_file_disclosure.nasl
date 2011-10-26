#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a CGI application that is affected by
an information disclosure vulnreability. 

Description :

The remote host is using webERP, a web-based accounting / ERP
software. 

There is a flaw in the version of webERP on the remote host such that
an attacker is able to download the application's configuration file,
'logicworks.ini', containing the database username and password. 

See also :

http://www.securityfocus.com/archive/1/313575

Solution : 

Upgrade to webERP 0.1.5 or newer.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


if (description)
{
 script_id(11639);
 script_bugtraq_id(6996);
 script_version ("$Revision: 1.6 $");

 script_name(english:"webERP Configuration File Remote Access");
 script_description(english:desc["english"]);
 script_summary(english:"Determines if webERP is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach d ( cgi_dirs() )
{
 req = http_get(item:d + "/logicworks.ini", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( res == NULL ) exit(0);
 if("$CompanyName" >< res && "WEB-ERP" >< res )
 	{
	  if (report_verbosity > 0) {
	    report = string(
	      desc["english"],
	      "\n\n",
	      "Plugin output :\n",
	      "\n",
	      res
	    );
	  }
	  else report = desc["english"];

	  security_warning(port:port, data:report);
	  exit(0);
	}
}
