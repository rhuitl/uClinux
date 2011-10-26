#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if(description)
{
  script_id(11929);
  script_version ("$Revision: 1.11 $");
 
  script_name(english:"SAP DB / MaxDB Detection");
 
  desc["english"] = "
Synopsis :

A SAP DB or MaxDB database server is listening on the remote port.

Description :

SAP DB or MaxDB, an ERP software,  is running on the remote
port.

See also :

http://www.sapdb.org/
http://www.mysql.com/products/maxdb/

Solution : 

If this service is not needed, disable it or filter incoming traffic
to this port.

Risk factor : 

None";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detect SAP DB / MaxDB server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  script_family(english:"Service detection");
  script_dependencies("find_service.nes");
  script_require_ports("Services/unknown", 7210);
  exit(0);
}

include("byte_func.inc");
include("misc_func.inc");
include("global_settings.inc");
##include("dump.inc");


if ( thorough_tests )
 port = get_unknown_svc(7210);
else 
 port = 7210;

if (!port) exit(0);
if (!get_tcp_port_state(port)) exit(0);


r = hex2raw(s:	"51000000035b00000100000000000000" +
		"000004005100000000023900040b0000" +
		"d03f0000d03f00000040000070000000" +
		"4e455353555320202020202020202020" +
		"0849323335333300097064626d73727600");

s = open_sock_tcp(port);
if ( ! s ) exit(0);
send(socket: s, data: r);

r2 = recv(socket: s, length: 64);
##dump(dtitle: "SAP", ddata: r2);
if (strlen(r2) < 7) exit(0);

if (
  (ord(r2[0]) == 0x40 || ord(r2[0]) == 0x43) &&
  substr(r2, 1, 6) == hex2raw(s: "000000035c00")
)
{
  security_note(port);
  register_service(port: port, proto: "sap_db_vserver");
}
close(s);
