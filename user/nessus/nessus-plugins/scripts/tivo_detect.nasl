#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote host is a personal video recorder (PVR).

Description :

The remote host is a TiVo, a personal video recorder.

Make sure the use of such devices is authorized by your corporate security
policy.

Risk factor : 

None";


if (description) {
  script_id(20813);
  script_version("$Revision: 1.5 $");

  name["english"] = "TiVo Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects a TiVo";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports(80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


if ( ! get_port_state(80) ) exit(0);
banner = get_http_banner(port:80);
if (! banner ) exit(0);

if ( "Server: tivo-httpd-" >< banner )
{
 version = egrep(pattern:"^Server: tivo-httpd", string:banner);
 os_version = ereg_replace(pattern:"^Server: tivo-httpd-1:(.*)", replace:"\1", string:version);

 report = desc['english'] + '\n\nPlugin output : \n' + 'The remote TiVO is running TiVO software version ' + os_version + '\n';
 security_note(port:80, data:report);
}
