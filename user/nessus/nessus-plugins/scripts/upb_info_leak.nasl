#
# This script was written by Erik Stephens <erik@edgeos.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(12198);
  script_bugtraq_id(6333);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"4928");
  script_version ("$Revision: 1.4 $");
  name["english"] = "Ultimate PHP Board Information Leak";
  script_name(english:name["english"]);
  desc["english"] = "
The remote host is running Ultimate PHP Board (UPB).

There is a flaw in this version which may allow an attacker to view
private message board information.

Solution : Upgrade to the latest version (http://www.myupb.com)
Risk factor : Low";
  script_description(english:desc["english"]);
  summary["english"] = "Checks for UPB";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 Edgeos, Inc.",
		   francais:"Ce script est Copyright (C) 2004 Edgeos, Inc.");
  family["english"] = "CGI abuses";
  family["francais"] = "Abus de CGI";
  script_family(english:family["english"], francais:family["francais"]);
  script_dependencies("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port) || !can_host_php(port:port))
  exit(0);

foreach d (make_list("/upb", "/board", cgi_dirs()))
{
  req = http_get(item:string(d, "/db/users.dat"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);
  if (egrep(pattern:"^Admin<~>", string:res))
  {
    security_hole(port);
    exit(0);
  }
}
