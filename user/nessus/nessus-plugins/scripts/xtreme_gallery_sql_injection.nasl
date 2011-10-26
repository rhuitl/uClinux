#
# (C) Tenable Network Security
#
# Ref: 
#Date: 15 Jan 2004 22:58:05 -0000
#From: <posidron@tripbit.org>
#To: bugtraq@securityfocus.com
#Subject: Xtreme ASP Photo Gallery


if(description)
{
 script_id(12020);
 script_bugtraq_id(9438);
 script_version("$Revision: 1.8 $");
 name["english"] = "SQL injection in XTreme ASP Photo Gallery";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an ASP script that is affected by a SQL
injection flaw. 

Description :

The remote host appears to be running XTreme ASP Photo Gallery.

There is a flaw in the version of this software installed on the remote
host that may allow anyone to inject arbitrary SQL commands, which may
in turn be used to gain administrative access on the remote host. 

See also : 

http://www.securityfocus.com/archive/1/350028

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection in XTreme ASP Photo Gallery";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


function check(req)
{
  # Make sure script exists.
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (buf == NULL) exit(0);

  if ("<title>Login - XTREME ASP Photo Gallery</title>" >< res) {
   host = get_host_name();
   variables = string("username='&password=y&Submit=Submit");
   req = string("POST ", req, " HTTP/1.1\r\n", 
   	      "Host: ", host, ":", port, "\r\n", 
 	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

   buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if(buf == NULL)exit(0);

   if("in query expression 'username=''' AND password='y'" >< buf && "80040e14" >< buf)
   	{
	security_warning(port);
	exit(0);
	}
 }
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);


if (thorough_tests) dirs = make_list("/photoalbum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  check(req:dir + "/admin/adminlogin.asp");
 }
