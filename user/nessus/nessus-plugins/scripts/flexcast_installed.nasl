#
# (C) Tenable Network Security
#


if (description) {
  script_id(18428);
  script_version("$Revision: 1.2 $");

  name["english"] = "FlexCast Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote server is an audio / video streaming application.

Description :

The remote host is running FlexCast, an audio/video streaming server. 

See also :

http://flexcast.virtualworlds.de/

Solution :

Make sure use of this program is in accordance with your corporate
security policy. 

Risk factor :

None";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for FlexCast";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000, 8001);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:8000);
if (!get_port_state(port)) exit(0);


# Check the banner for FlexCast.
banner = get_http_banner(port:port);
if (banner && "Server: FlexCast Server/" >< banner)
  security_note(port);
