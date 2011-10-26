#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

A syslog server is listening on the remote host. 

Description :

The remote host is running a syslog service from eIQnetworks
Enterprise Security Analyzer (ESA), a security information and event
management application. 

Note that eIQnetworks Enterprise Security Analyzer is also included in
third-party products such as Astaro Report Manager, Fortinet
FortiReporter, and iPolicy Security Reporter. 

See also :

http://www.eiqnetworks.com/products/EnterpriseSecurityAnalyzer.shtml

Risk factor :

None";


if (description)
{
  script_id(22126);
  script_version("$Revision: 1.2 $");

  script_name(english:"eIQnetworks Enterprise Security Analyzer Syslog Server Detection");
  script_summary(english:"Detects an eIQnetworks Enterprise Security Analyzer Syslog Server");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 10617);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(10617);
  if (!port) exit(0);
}
else port = 10617;
if (!get_tcp_port_state(port)) exit(0);


# Try to get some interesting information.
info = "";
soc = open_sock_tcp(port);
if (!soc) exit(0);

send(socket:soc, data:"GETVERSION");
res = recv(socket:soc, length:256);
close(soc);

if (res && res =~ "[0-9]~[0-9]")
{
  ver = res;
  if ("Version:" >< res)
  {
    ver = ver - strstr(ver, '\n');
    info = strstr(res, "Version:");
  }
  else 
  {
    info = "Version : " + str_replace(find:"~", replace:' (', string:res) + ')\n';
  }
}


# If we got some info from the remote host...
if (info)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"esa_syslog");
  set_kb_item(name:"ESA/Syslog/"+port+"/Version", value:ver);

  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    info
  );

  security_note(port:port, data:report);
}
