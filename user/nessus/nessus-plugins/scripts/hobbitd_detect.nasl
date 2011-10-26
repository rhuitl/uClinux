#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

A Hobbit server is listening on the remote host. 

Description :

The remote host is running the server component of Hobbit Monitor, an
open-source application and network monitoring tool.

See also :

http://hobbitmon.sourceforge.net/

Solution :

Consider restricting access to this service to the localhost, which is
the default configuration. 

Risk factor :

None";


if (description)
{
  script_id(22180);
  script_version("$Revision: 1.2 $");

  script_name(english:"Hobbit Monitor Daemon Detection");
  script_summary(english:"Detects a Hobbit Monitor daemon");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 1984);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("raw.inc");


if (thorough_tests) {
  port = get_unknown_svc(1984);
  if (!port) exit(0);
}
else port = 1984;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a request for a config file.
file = "hobbitserver.cfg";
filter = string("tcp and src ", get_host_ip(), " and src port ", port);
res = send_capture(socket:soc, data:string("config ", file), pcap_filter:filter);
if (res == NULL) exit(0);
flags = get_tcp_element(tcp:res, element:"th_flags");
if (flags & TH_ACK == 0) exit(0);


# Half-close the connection so the server will send the results.
ip = ip();
seq = get_tcp_element(tcp:res, element:"th_ack");
tcp = tcp(
  th_dport : port,
  th_sport : get_source_port(soc),
  th_seq   : seq,
  th_ack   : seq,
  th_win   : get_tcp_element(tcp:res, element:"th_win"),
  th_flags : TH_FIN|TH_ACK
);
halfclose = mkpacket(ip, tcp);
send_packet(halfclose, pcap_active:FALSE);
res = recv(socket:soc, length:65535);
if (res == NULL) exit(0);


# It's a hobbit server if the result looks like a config file.
if (egrep(pattern:'^ *(HOBBITCLIENTHOME|HOBBITLOGO|USEHOBBITD) *=', string:res))
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"hobbitd");

  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "Here are the contents of hobbitd's ", file, " that Nessus was\n",
    "able to retrieve from the remote host :\n",
    "\n",
    res
  );

  security_note(port:port, data:report);
}
