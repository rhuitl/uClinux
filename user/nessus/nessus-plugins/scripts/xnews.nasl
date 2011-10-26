#
# This script was written by Audun Larsen <larsen@xqus.com>
#

if(description)
{
 script_version ("$Revision: 1.8 $");
 script_id(12068);
 script_cve_id("CVE-2002-1656");
 script_bugtraq_id(4283);
 name["english"] = "x-news 1";
 name["francais"] = "x-news 1";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
information disclosure. 

Description :

X-News is a news management system, written in PHP.  X-News uses a
flat-file database to store information.  It will run on most Unix and
Linux variants, as well as Microsoft Windows operating systems. 

X-News stores user ids and passwords, as MD5 hashes, in a world-
readable file, 'db/users.txt'.  This is the same information that is
issued by X-News in cookie-based authentication credentials.  An
attacker may incorporate this information into cookies and then submit
them to gain unauthorized access to the X-News administrative account. 

See also :

http://www.ifrance.com/kitetoua/tuto/x_holes.txt

Solution :

Deny access to the files in the 'db' directory through the webserver. 

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 summary["english"] = "Check if version of x-news 1.x is installed";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Audun Larsen");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


if (thorough_tests) dirs = make_list("/x-news", "/x_news", "/xnews", "/news", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 req = http_get(item:string(dir, "/x_news.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( res == NULL ) exit(0);

 if("Powered by <a href='http://www.xqus.com'>x-news</a> v.1\.[01]" >< res)
 {
   req2 = http_get(item:string(dir, "/db/users.txt"), port:port);
   res2 = http_keepalive_send_recv(port:port, data:req2, bodyonly:TRUE);
   if( res2 == NULL ) exit(0);
   if("|1" >< res2)
   {
      security_warning(port);
      exit(0);
   } 
  } 
}
