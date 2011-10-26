#
#
# This script is (C) 2003 Renaud Deraison
#
#
# This plugin positively identifies notes-to-notes communication (on top
# of port 1352)

if (description)
{
 script_id(11410);
 script_version ("$Revision: 1.2 $");
 script_name(english:"Notes detection");
 desc["english"] = "
A Lotus Domino server is listening on this port

Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is Domino");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_require_ports(1352);
 exit(0);
}

include("misc_func.inc");

port = 1352;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 
 req = raw_string(0x3A, 0x00,
 		  0x00, 0x00, 0x2F, 0x00, 0x00, 0x00, 0x02, 0x00,
		  0x00, 0x40, 0x02, 0x0F, 0x00, 0x01, 0x00, 0x3D,
		  0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x2F, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
		  0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00);
		  
 send(socket:soc, data:req);
 r = recv(socket:soc, length:2);
 if(!r)exit(0);
 
 len = ord(r[0]) + ord(r[1])*256;
 r = recv(socket:soc, length:len);
 close(soc);
 if("CN=" >< r)
 {
  r = strstr(r, "CN=");
  for(i=0;i<strlen(r);i++)
  {
   if(ord(r[i]) < 10)break;
   else name += r[i];
  }
  
  report = "A domino server (" + name + ") is listening on this port";
  security_note(port:port, data:report);
  register_service(port:port, proto:"notes");
 }
}
