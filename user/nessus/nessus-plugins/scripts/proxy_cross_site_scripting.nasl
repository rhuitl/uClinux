#
# Source: cross_site_scripting.nasl
#

if (description)
{
 script_id(11634);
 script_cve_id("CVE-2003-0292");
 script_bugtraq_id(7596);
 script_version("$Revision: 1.3 $");
 script_name(english:"Proxy Web Server Cross Site Scripting");
 desc["english"] = "
The remote proxy (or web server) seems to be vulnerable to the Cross Site 
Scripting vulnerability (XSS). The vulnerability is caused by the result 
returned to the user when a non-existing file is requested (e.g. the result contains the 
JavaScript providedin the request) on a non-existing server.
The vulnerability would allow an attacker to make the server present the user with 
the attacker's JavaScript/HTML code.
Since the content is presented by the server, the user will give it the 
trust level of the server (for example, the trust level of banks, shopping centers, etc. 
would usually be high).

Risk factor : Medium";


 script_description(english:desc["english"]);
 script_summary(english:"Determine if the remote proxy is vulnerable to Cross Site Scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.", francais:"Divers");
 script_copyright(english:"(c) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", "Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/http_proxy"), port:8080);
foreach port (ports)
{
dir[0] = ".jsp";
dir[1] = ".shtml";
dir[2] = ".thtml";
dir[3] = ".cfm";
dir[4] = "";

if(get_port_state(port))
{
 for (i = 0; dir[i] ; i = i + 1)
 {
  soc = http_open_socket(port);
  if(soc)
   {
    url = string("http://xxxxxxxxxxx./<SCRIPT>alert('Vulnerable')</SCRIPT>", dir[i]);
    
    confirmtext = string("<SCRIPT>alert('Vulnerable')</SCRIPT>"); 
    req = http_get(item:url, port:port);
    send(socket:soc, data:req);
    head = http_recv_headers2(socket:soc);
    r = http_recv(socket:soc);
    http_close_socket(soc);

    
    if(confirmtext >< r)
      {
       security_warning(port);
       set_kb_item(name:string("www_proxy/", port, "/generic_xss"), value:TRUE);
       break;
      }
   }
   else break;
  }
 }
}

