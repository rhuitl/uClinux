#
# (C) Tenable Network Security
#

if (description) {
  script_id(19701);
  script_version("$Revision: 1.2 $");

  name["english"] = "HP OpenView UI Process Manager Daemon Detection";
  script_name(english:name["english"]);
  
  desc["english"] = "
Synopsis :

An HP OpenView UI Process Manager Daemon is listening on this port.

Description :

The remote host is running an HP OpenView UI Process Manager daemon on 
this port.


Solution :

If this service is not needed, disable it or filter incoming traffic
to this port.

Risk factor : 

None";
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for HP OpenView UI Process Manager Daemon";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_dependencies ("find_service2.nasl");
  script_require_ports(7777);
  exit(0);
}

include ("misc_func.inc");
include ("network_func.inc");

port = 7777;

if (!service_is_unknown (port:port))
  exit (0);


## functions ##

function set_int (i)
{
 return htonl(n:4) + htonl(n:i);
}

function set_string (s)
{
 return htonl(n:strlen(s)) + s;
}

function set_parameter_uint (u)
{
 return set_int (i:2) + # type (2) -> uint
        set_int (i:u);
}

function set_parameter_string (s)
{
 return set_int (i:1) +         # type (1) -> string
        set_int (i:strlen(s)) + # length of string
        set_string (s:s);
}


## Main code ##

soc = open_sock_tcp (port);
if (!soc) exit (0);

req = set_int (i:1) +
      set_int (i:2) +
      set_int (i:3) +
      set_int (i:5) +                     # parameter number
      set_parameter_uint (u:0) +          # param1 -> uint
      set_parameter_string (s:"nessus") + # param2 -> string
      set_parameter_string (s:"nessus") + # param3 -> string
      set_parameter_uint (u:0) +          # param4 -> uint
      set_parameter_uint (u:0) +          # param5 -> uint
      set_int (i:2) ;                     # packet type (2) -> 5 param (uint,string,string,uint,uint)

send (socket:soc, data:req);
buf = recv(socket:soc, length:0x20);

if ("0000001c0000000100000007000000000000000100000002fffffff600000002" >< hexstr(buf))
{
  register_service (port:port, proto:"ovuispmd");
  security_note(port);
}
