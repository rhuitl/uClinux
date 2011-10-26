#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

A ZABBIX server is listening on the remote host. 

Description :

The remote host is running a ZABBIX server.  ZABBIX is an open-source
network monitoring application, and a ZABBIX server is used to collect
information from agents on hosts being monitored. 

See also :

http://www.zabbix.com/

Solution :

Limit incoming traffic to this port if desired. 

Risk factor :

None";


if (description)
{
  script_id(22526);
  script_version("$Revision: 1.1 $");

  script_name(english:"ZABBIX Server Detection");
  script_summary(english:"Detects a ZABBIX server");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/unknown", 10051);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(10051);
  if (!port) exit(0);
}
else port = 10051;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Simulate a connection from an agent.
req = string("ZBX_GET_ACTIVE_CHECKS\n", SCRIPT_NAME, "-", unixtime());
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);


# It's a ZABBIX server if the response is "ZBX_EOF".
if (res && res == 'ZBX_EOF\n')
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"zabbix_server");

  security_note(port);
}
