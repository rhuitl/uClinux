#
# This script was written by Filipe Custodio <filipecustodio@yahoo.com>
#
# See the Nessus Scripts License for details
#
# Changes by rd :
# - description slightly modified to include a solution

if(description)
{
 script_id(10492);
 script_bugtraq_id(1065);
 script_cve_id("CVE-2000-0071");
 script_version ("$Revision: 1.23 $");

 name["english"] = "IIS IDA/IDQ Path Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
IIS 4.0 allows a remote attacker to obtain the real pathname
of the document root by requesting non-existent files with
.ida or .idq extensions.

An attacker may use this flaw to gain more information about
the remote host, and hence make more focused attacks.

Solution: Select 'Preferences ->Home directory ->Application',
and check the checkbox 'Check if file exists' for the ISAPI
mappings of your server.
	  
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines IIS IDA/IDQ Path Reveal vulnerability";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000 Filipe Custodio");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


sig = get_http_banner(port:port);
if ( "IIS" >!< sig ) exit(0);


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 
 req = http_get(item:"/anything.idq", port:port);
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 str = egrep( pattern:"^<HTML>", string:r ) - "<HTML>";
 str = tolower(str);
  
 if ( egrep(pattern:"[a-z]\:\\.*anything",string:str) ) {
   security_warning( port:port );
 } else {
   req = http_get(item:"/anything.ida", port:port);
   soc = http_open_socket(port);
   if(!soc)exit(0);
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   str = egrep( pattern:"^<HTML>", string:r ) - "<HTML>";
   str = tolower(str);
   if ( egrep(pattern:"[a-z]\:\\.*anything", string:str) )
      security_warning( port:port );
   }
}
