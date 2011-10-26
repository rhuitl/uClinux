#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The remote web server is running an OpenView service.

Description :

The remote host appears to be running one of the HP OpenView Product.

This specific service is an HTTP server. By sending special requests
(version, info, status, ping, services, ...), it is possible to
obtain informations about the remote host.

Risk factor :

None";


if (description)
{
 script_id(22318);
 script_version("$Revision: 1.4 $");

 script_name(english:"HP OpenView BBC service detection");
 script_summary(english:"Checks for HP OpenView BBC services");
 
 script_description(english:desc["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

 script_dependencies("http_version.nasl");
 script_require_ports(383, 3013, 3565);

 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

ports = make_list (383, 3013, 3565);

foreach port (ports)
{
 if (!get_port_state(port))
   continue;

 if ("BBC" >!< get_http_banner (port:port))
   continue;

 # can't use http_get else the response is in HTML format
 req = string ("GET /Hewlett-Packard/OpenView/BBC/version HTTP/1.0\r\n\r\n");
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE, embedded:TRUE);
 if (!res || "HP OpenView HTTP Communication Version Report" >!< res)
   continue;

 report = string (desc["english"],
	"\n\nPlugin output :\n\n",
	"The following version information have been extracted from the service :\n\n",
	res);

 security_note (port:port, data:report);
}
