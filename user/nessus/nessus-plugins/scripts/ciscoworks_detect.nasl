#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19559);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "CiscoWorks Management Console Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running CiscoWorks, a LAN Management Solution,
on this port

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for CiscoWorks";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 TNS");
 
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("httpver.nasl");
 script_require_ports("Services/www", 1741);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");


port = get_kb_item("Services/www");
if ( ! port ) port = 1741;

if(get_port_state(port))
{
  req = http_get(item:"/login.html", port:port);
  soc  = open_sock_tcp(port);
  if ( ! soc ) exit(0);
  send(socket:soc, data:req);
  res = http_recv(socket:soc);

  if("<title>CiscoWorks</title>" >< res )
  {
    security_note(port);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
  }
}
