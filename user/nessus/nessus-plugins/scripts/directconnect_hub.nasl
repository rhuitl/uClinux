#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2

if(description)
{
  script_id(13751);
  script_version ("$Revision: 1.5 $");
 
  script_name(english:"Direct Connect hub detection");
 
  desc["english"] = "
Synopsis :

The remote host contains a peer-to-peer filesharing application. 

Description :

A Direct Connect 'hub' (or server) is running on this port.  Direct
Connect is a protocol used for peer-to-peer file-sharing as well as
chat, and a hub routes communications among peers.  While any type of
file may be shared, Direct Connect hubs often handle movies, images,
music files, and games, which may not be suitable for use in a
business environment. 

See also :

http://en.wikipedia.org/wiki/Direct_connect_file-sharing_application

Solution :

Make sure use of this program is in accordance with your corporate
security policy. 

Risk factor :

None";
  script_description(english:desc["english"]);
 
  summary["english"] = "Direct Connect hub detection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  family["english"] = "Peer-To-Peer File Sharing";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes");
  script_require_ports("Services/DirectConnectHub", 411);

  exit(0);
}



port = get_kb_item("Services/DirectConnectHub");
if (!port) port = 411;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if(soc)
{
	r=recv_line(socket:soc, length:1024);
	if ( ! r ) exit(0);
	if (ereg(pattern:"^\$Lock .+",string:r))
	{
		# Disconnect nicely.
		str="$quit|";
		send(socket:soc,data:str);

		security_note(port);
	}
	close(soc);
}
