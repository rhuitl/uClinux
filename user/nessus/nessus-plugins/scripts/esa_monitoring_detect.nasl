#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22195);
  script_version("$Revision: 1.2 $");

  script_name(english:"eIQnetworks Enterprise Security Analyzer Monitoring Agent Detection");
  script_summary(english:"Detects an eIQnetworks Enterprise Security Analyzer Monitoring Agent");

  desc = "
Synopsis :

A monitoring agent is listening on the remote host. 

Description :

The remote host is running a monitoring agent from eIQnetworks
Enterprise Security Analyzer (ESA), a security information and event
management application. 

Note that eIQnetworks Enterprise Security Analyzer is also included in
third-party products such as Astaro Report Manager, Fortinet
FortiReporter, and iPolicy Security Reporter. 

See also :

http://www.eiqnetworks.com/products/EnterpriseSecurityAnalyzer.shtml

Risk factor :

None";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 10626);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(10626);
  if ( ! port ) exit(0);
}
else port = 10626;
if (!get_tcp_port_state(port)) exit(0);


# Make sure it looks like the Monitoring Agent.
soc = open_sock_tcp(port);
if (!soc) exit(0);

cmd = string("QUERYMONITOR&nessus&", SCRIPT_NAME, "&&");
send(socket:soc, data:cmd);
res = recv(socket:soc, length:64);
close(soc);


# If it looks like the service...
if (egrep(pattern:"^-~(\^)?Recent (Virus Detections|Emergency Events)$", string:res))
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"esa_monitoring");
  security_note(port);
}
