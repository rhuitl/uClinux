#
# This script was written by Andrew Hintz <http://guh.nu>
# (It is based on Renaud's template.)
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11193);
 script_bugtraq_id(6323);
 script_version ("$Revision: 1.3 $");

 name["english"] = "akfingerd";
 script_name(english:name["english"]);
 desc["english"] = "
The remote finger service appears to vulnerable to a remote
attack which can disrupt the service of the finger daemon.
This denial of service does not effect other services that
may be running on the remote computer, only the finger
service can be disrupted.

akfingerd version 0.5 or earlier is running on the remote
host.  This daemon has a history of security problems, 
make sure that you are running the latest version of 
akfingerd.

Versions 0.5 and earlier of akfingerd are vulnerable to a
remote denial of service attack.  They are also vulnerable
to several local attacks.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Finger daemon DoS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); #This script should not disrupt the machine at all
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Andrew Hintz");
 family["english"] = "Finger abuses";
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
  buf = string("nessusIs4Scanning2You@127.0.0.1@127.0.0.1\r\n"); #send request for forwarded finger query
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:96);
  close(soc);
  if("Forwarding is not supported." >< data) #check for forwarding-denial message used by akfingerd
  {
   soc1 = open_sock_tcp(port); #start a connection and leave it open
   if(soc1)
   {
    soc2 = open_sock_tcp(port); #start another connection and issue a request on it
    if(soc2)
    {
     send(socket:soc2, data:buf);
     data2 = recv(socket:soc2, length:96);
     if(!data2) security_warning(port);  #akfingerd won't send a reply on second connection while the first is still open
     close(soc2);
    }
    else security_warning(port);
    close(soc1);
   }
  }
 }
}
