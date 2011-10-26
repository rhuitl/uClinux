#
# This script was written by Michel Arboi <arboi@alussinan.org> 
#
# GPL, blah blah blah
#

if(description)
{
 script_id(11175);
 script_version ("$Revision: 1.9 $");

 name["english"] = "Too long line";
 name["francais"] = "Ligne trop longue";
 
 script_name(english:name["english"],
            francais:name["francais"]);
 
 desc["english"] = "
It was possible to kill the service by sending a single long 
text line.
A cracker may be able to use this flaw to crash your software
or even execute arbitrary code on your system.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes a service by sending a too long line";
 summary["francais"] = "Tue un service en envoyant une ligne trop longue";
 script_summary(english:summary["english"],
               francais:summary["francais"]);
 
 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";

 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes");
 exit(0);
}

#

include('misc_func.inc');
ports = get_kb_list("Services/unknown");
if(isnull(ports))exit(0);

line = string(crap(512), "\r\n");

foreach port (make_list(ports))
{
    if ( service_is_unknown(port:port) && port != 135 && port != 139 && port != 445 ) 
    {
    port = int(port);
    s = open_sock_tcp(port);
    if (s)
    {
      send(socket: s, data: line);
      r = recv(socket:s, length:1); # Make sure data arrived
      close(s);
      s = open_sock_tcp(port);
      if (s) { close(s); }
      else { security_hole(port); }
    }
   }
}
