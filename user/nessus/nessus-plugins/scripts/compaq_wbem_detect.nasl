#
# (C) Tenable Network Security
#

desc["english"] = "
Synopsis :

A Compaq Web Management server is listening on the remote port.

Description :

The remote host is running Compaq Web Management, a web-based 
interface to configure various components of the remote host.

It is suggested to not allow anyone to connect to this service.

Solution :

Filter incoming traffic to this port.

Risk factor : 

None";




if(description)
{
 script_id(10746);
 script_version ("$Revision: 1.9 $");

 name["english"] = "Compaq Web Management Server";
 script_name(english:name["english"]);
 script_description(english:desc["english"]);
 summary["english"] = "Determines of the remote web server is Compaq Web Management";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", 2301, 2381);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("misc_func.inc");
 
ports = add_port_in_list(list:get_kb_list("Services/www"), port:2301);
ports = add_port_in_list(list:ports, port:2381);
foreach port (ports)
{
  banner = get_http_banner(port:port);
  if ( ! banner || "Server: CompaqHTTPServer" >!< banner ) continue;
  if ( version = egrep(pattern:"^Server: CompaqHTTPServer/", string: banner ) )
  {
    version = ereg_replace(pattern:"Server: CompaqHTTPServer/(.*)", string:version, replace:"\1");
    report = desc["english"] + '\n\nPlugin output:\n\nThe remote version of the Compaq Web Management server is : ' + version;
    security_note(port:port, data:report);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
  }
}
