#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11691);
 script_version ("$Revision: 1.9 $");
 name["english"] = "Desktop Orbiter Server Detection";
 script_name(english:name["english"]);

 
 desc["english"] = "
The remote host is running a Desktop Orbiter Satellite

This service could be used by an attacker to partially take
control of the remote system, as it is not password protected.

Solution : Disable this service
Risk factor : High";


  script_description(english:desc["english"]);


   summary["english"] = "Checks for the presence Desktop Orbiter";
   script_summary(english:summary["english"]);


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");

 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("os_fingerprint.nasl", "find_service2.nasl");
 script_require_ports("Services/unknown", 51051);
 exit(0);
}

include("misc_func.inc");
include('global_settings.inc');

os = get_kb_item("Host/OS/icmp");
if(os)
{
 if("Windows" >!< os)exit(0);
}

function probe(port)
{
 if(get_port_state(port) == 0 ) return(0);
 soc = open_sock_tcp(port);
 if(!soc)return(0);
 send(socket:soc, data:raw_string(0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

req = '<?xml version = "1.0"?>\r\n\r
<Request version = "1.0" timestamp = "6/3/2003 10:14:11 AM">\r
    <param id = "_ActionId" value = "PING" type = "string"/>
</Request>';

send(socket:soc, data:req);
r = recv(socket:soc, length:8);
if(strlen(r) != 8 )exit(0);
len = ord(r[0]);
r = recv(socket:soc, length:len);
if("Reply version" >< r) { security_hole(port); register_service(port:port, proto:"desktop-orbiter"); }
}



if ( thorough_tests ) ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:51051);
else {
	if ( ! get_port_state(51051) ) exit(0);
	ports = make_list(51051);
     }

foreach port (ports)
{
 if ( port != 135 && port != 139 && port != 445 ) probe(port:port);
}
