#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(21562);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2006-2351", "CVE-2006-2352", "CVE-2006-2353", "CVE-2006-2354", "CVE-2006-2355", "CVE-2006-2356", "CVE-2006-2357");
 script_bugtraq_id(17964);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"25469");
   script_xref(name:"OSVDB", value:"25470");
   script_xref(name:"OSVDB", value:"25471");
   script_xref(name:"OSVDB", value:"25472");
 }

 name["english"] = "Ipswitch WhatsUp Professional Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis:

The remote web server is affected by multiple flaws. 

Description :

The remote host appears to be running Ipswitch WhatsUp Professional,
which is used to monitor states of applications, services and hosts. 

The version of WhatsUp Professional installed on the remote host is
prone to multiple issues, including source code disclosure and
cross-site scripting vulnerabilities. 

See also: 

http://www.securityfocus.com/archive/1/433808/30/0/threaded
http://www.ipswitch.com/products/whatsup/professional/

Solution :

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Ipswitch WhatsUp Professional Information Disclosure";
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

#code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8022);
if (!get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if ("Server: Ipswitch" >!< banner) exit(0);

req = http_get(item:"/NmConsole/Login.asp.", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if( r == NULL )exit(0);

if (
  'SOFTWARE\\\\Ipswitch\\\\Network Monitor\\\\WhatsUp' >< r &&
  (
    '<%= app.GetDialogHeader("Log In") %>' >< r ||
    egrep(pattern:'<%( +if|@ +LANGUAGE="JSCRIPT")', string:r)
  )
)
  security_note(port);
