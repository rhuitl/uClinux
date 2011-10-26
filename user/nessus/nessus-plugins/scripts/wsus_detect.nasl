#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#
# Changes by Tenable Network Security :
#
# - "Services/www" check
# - Family changed to "Service detection"
# - Request fixed

if(description)
{
 script_id(20377);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "Windows Server Update Services detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis:

The remote host appears to be running Windows Server Update
Services.

Description:

This product is used to deploy easily and quickly latest 
Microsoft product updates.

See also: 

http://www.microsoft.com/windowsserversystem/updateservices/default.mspx

Risk factor : 

None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for WSUS console";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 David Maciejak");
 
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80, 8530);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

ports = get_kb_list ("Services/www");

if (isnull(ports))
  ports = make_list (8530);
else
  ports = make_list (8530, ports);


foreach port (ports)
{
 if(get_port_state(port))
 {
  req = http_get(item:"/Wsusadmin/Errors/BrowserSettings.aspx", port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL )exit(0);

  if ( egrep (pattern:'<title>Windows Server Update Services error</title>.*href="/WsusAdmin/Common/Common.css"', string:r) ||
       egrep (pattern:'<div class="CurrentNavigation">Windows Server Update Services error</div>', string:r) )
  {
   security_note(port);
  }
 }
}

