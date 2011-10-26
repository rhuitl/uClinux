#
# (C) Tenable Network Security
#
if(description)
{
  script_id(15438);
  script_bugtraq_id(11352);
 script_version ("$Revision: 1.2 $");
  script_name(english:"Helix Universal Server Remote Integer Handling DoS");
  desc["english"] = "
The remote host is running Helix Universal Server, a digital media
delivery platform.

There is a flaw in the remote version of this software which 
may allow an attacker to crash this service by sending a 
malformed POST request to the remote host.

Solution : Upgrade to the most recent version of RealServer
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks the version of the remote HelixServer");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is (C) 2004 Tenable Network Security");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/http", 8080);   #port 7070, which may be indicative of server on 8080
  exit(0);
}



#
# The script code starts here
include("http_func.inc");

port = get_http_port(default:8080);
if ( ! port || ! get_port_state(port) ) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( egrep(pattern:"^Server: Helix Server Version ([0-8]\.[0-9]\..*|9\.0\.([0-3]|4\.([0-8]|9([0-4]|5[0-8])))|10\.([0-2]|3\.(0\.|1\.([0-6]|7(0|1[0-6])))))", string:banner) ) security_warning(port);
