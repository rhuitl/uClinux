#
# This script was written by Renaud Deraison <deraison@nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10728);
 script_version ("$Revision: 1.8 $");
 name["english"] = "Determine if Bind 9 is running";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to determine that the remote BIND
server is running bind 9.x by querying it for the AUTHORS
map.

It is recommended you change the source code to prevent
attackers from fingerprinting your server.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determine which version of BIND name daemon is running";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencies("bind_version.nasl");
 script_exclude_keys("bind/version");
 script_require_keys("DNS/udp/53");

 exit(0);
}

#
# The script code starts here
#
#
# We try to gather the version number via TCP first, and if this
# fails (or if the port is closed), we'll try via UDP
#
#


 soctcp53 = 0;
 
 if(get_port_state(53))
  {
  soctcp53 = open_sock_tcp(53);
 }
 if(!soctcp53){
  if(!(get_udp_port_state(53)))exit(0);
  socudp53 = open_sock_udp(53);
  soc = socudp53;
  offset = 0;
  }
  else {
  	soc = soctcp53;
	offset = 2;
  	}
  
 if (soc)
 {
  
  raw_data = raw_string(
			0x00, 0x0A, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x07);
  
  if(offset)raw_data = raw_string(0x00, 0x1E) + raw_data;
  
  raw_data = raw_data + "AUTHORS";
  raw_data = raw_data + raw_string( 0x04 );
  raw_data = raw_data + "BIND";
  raw_data = raw_data + raw_string(
				   0x00, 0x00, 0x10, 0x00, 0x03);

  send(socket:soc, data:raw_data);
  result = recv(socket:soc, length:1000);
  if("Bob Halley" >< result)
  {
   set_kb_item(name:"bind/version", value:"9");
   security_note(53);
  }
 close(soc);
 }


