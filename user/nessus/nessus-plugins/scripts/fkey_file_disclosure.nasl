#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16224);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(12321);
 name["english"] = "FKey Remote Arbitrary File Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of the finger daemon (possibly 'fkey') allows users
to read arbitrary files by supplying a file name shorter than 10 chars.

Solution : Disable this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "fkey file disclosure";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security"); 
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("/etc/group\r\n");

  send(socket:soc, data:buf);
  data = recv(socket:soc, length:2048);
  close(soc);
  if ( egrep(pattern:"^bin:.:", string:data)  &&
       egrep(pattern:"^tty:.:", string:data)  &&
       egrep(pattern:"^nobody:.:", string:data)  )
	{
	report = "
It is possible to force the remote finger daemon (possibly fkey) to
disclose the content of several files on the remote host, by
supplying the file name. 

For intance, requesting the file /etc/group yields : 

" + data +  "

Solution : Disable this service
Risk Factor : High";
	security_hole(port:port, data:report);
 	}
   } 
}
