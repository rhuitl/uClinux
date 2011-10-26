#
# Copyright (C) 2004 Tenable Network Security
#

if(description)
{
  script_id(12115);
  script_version ("$Revision: 1.4 $");

  name["english"] = "Unreal Tournament Server Detection";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running a version of Unreal Tournament Server.
The Server is used to host Internet and Local Area Network (LAN)
games.  

Solution : Ensure that this sort of network gaming is in alignment
with Corporate and Security Policies. 
Risk factor : Low";


  script_description(english:desc["english"]);
  summary["english"] = "Detects Unreal Tournament Server";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


# start script
include("http_func.inc");

port = get_http_port(default:80);
if (!port) exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);

if (egrep(string:banner, pattern:"^Server: UnrealEngine UWeb Web Server Build")) security_note(port); 
