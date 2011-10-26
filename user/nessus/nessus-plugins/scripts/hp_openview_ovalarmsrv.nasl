#
# (C) Tenable Network Security
#

if (description) {
  script_id(19706);
  script_version("$Revision: 1.4 $");

  name["english"] = "HP OpenView NNM Alarm Service Detection";
  script_name(english:name["english"]);
  
  desc["english"] = "
Synopsis :

An HP OpenView Network Node Manager is listening on this port.

Description :

The remote host is running the HP OpenView Network Node Management 
Alarm Service. This service is part of the HP OpenView Management suite.

Solution :

If this service is not needed, disable it or filter incoming traffic to this port.

Risk factor : 

None";
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for HP OpenView NNM Alarm Service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_require_ports(2953,2954);
  exit(0);
}

include ("misc_func.inc");

# first port detection


port = 2953;

if (get_port_state(port))
{
 soc = open_sock_tcp (port);
 if (soc)
 {
  data = string("0:0:EVENTS\n");

  send (socket:soc, data:data);
  buf = recv (socket:soc, length:100);

  if (egrep(pattern:"[0-9]:.*:[0-9]+:.*:id:[0-9]+$", string:buf))
  {
   register_service (port:port, proto:"ovalarmsrv");
   security_note(port);
  }
  
  close(soc);
 }
}


# second port detection

port = 2954;

if (!get_port_state(port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

rep = string ("38\n");
data = string("35 4 nessus\n");

send (socket:soc, data:data);
buf = recv (socket:soc, length:4);

if ((strlen(buf) == 3) && (rep >< buf))
{
  register_service (port:port, proto:"ovalarmsrv");
  security_note(port);
}
