#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#
if(description)
{
 script_id(17200);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "Trend Micro IWSS console management detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to run the Trend Micro Interscan Web Security Suite.

Make sure that only authorized hosts can connect to this service, as the
information of its existence may help an attacker to make more sophisticated
attacks against the remote network.

Solution : Filter incoming traffic to this port
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Trend Micro IWSS web console management";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("httpver.nasl");

 script_require_ports(1812);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = 1812;
if(get_port_state(port))
{
 req = http_get(item:"/logon.jsp", port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);
 if("<title>Trend Micro InterScan Web Security Suite</title>" >< rep)
 {
   security_note(port);
   set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
 }
}
