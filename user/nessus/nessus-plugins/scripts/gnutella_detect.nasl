#
# Copyright 2002 by Michel Arboi <arboi@alussinan.org>
#
# See the Nessus Scripts License for details
#
#

desc["english"] = "
We detected a Gnutella 'servent'.
This file sharing software works in peer to peer mode.

Risk factor : Low";



if(description)
{
 script_id(10946);
 script_version ("$Revision: 1.14 $");

 name["english"] = "Gnutella servent detection";
 script_name(english:name["english"]);

 
 script_description(english:desc["english"]);

 summary["english"] = "Detect Gnutella servent";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 # Gnutella servent _might_ be detected as a web server
 script_require_ports("Services/www", 6346);
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
include("http_func.inc");

function check(port)
{
 if (! get_port_state(port))
  return (0);

 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:string("GNUTELLA CONNECT/0.4\r\n\r\n"));
  answer = recv(socket:soc, length:500);
  close(soc);
  # display(string(">", answer, "<\n"));

  if ("GNUTELLA OK" >< answer)
  {
   security_note(port:port, protocol:"tcp");
   register_service(port:port, proto:"gnutella");
   return(1);
  }
 }
 else exit(0);

 banner = get_kb_item(string("www/banner/", port));
 if(!banner)
 {
  if(get_port_state(port))
  {
   soc = open_sock_tcp(port);
   if(soc)
   {
    send(socket:soc, data:string("GET / HTTP/1.0\r\n\r\n"));
    banner = http_recv(socket:soc);
    close(soc);
   }
   else exit(0);
  }
 }
 
 
 if (! banner)
  return(0);

 # We should probably add more regex here. But there are 100+ Gnutella
 # softwares
 if (egrep(pattern:"Gnutella|BearShare", string:banner, icase:1))
 {
report = "Although this service did not answer to Gnutella protocol 0.4,
it might be a Gnutella server.

Risk factor : None";

  security_note(port:port, protocol:"tcp",data:report);
  return(1);
 }
}


ports = add_port_in_list(list:get_kb_list("Services/www"), port:6346);
foreach port (ports) check(port:port);
