#
# This script was written by Randy Matz <rmatz@ctusa.net>
#
# Improvement by rd: look in every dir for info.php and phpinfo.php
# not just in cgi-bin

if(description)
{
 script_version ("$Revision: 1.6 $");
 script_id(11229);
 
 name["english"] = "phpinfo.php";
 name["francais"] = "phpinfo.php";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "
Many PHP installation tutorials instruct the user to create
a file called phpinfo.php.  This file is often times left in 
the root directory after completion.
Some of the information that can be garnered from this file 
includes:  The username of the user who installed php, if they 
are a SUDO user, the IP address of the host, the web server 
version, The system version(unix / linux), and the root 
directory of the web server.

Solution : remove it
Risk factor : Low";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for the presence of phpinfo.php";
 summary["francais"] = "Vérifie la présence de phpinfo.php";
 script_summary(english:summary["english"], francais:summary["francais"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003 Randy Matz",
                francais:"Ce script est Copyright (C) 2003 Randy Matz");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencies("http_version.nasl");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs))dirs = make_list("");
else dirs = make_list("", dirs);

rep = NULL;

foreach dir (dirs)
{
 req = http_get(item:string(dir, "/phpinfo.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("<title>phpinfo()</title>" >< res)
 	rep += dir + '/phpinfo.php\n';

  req = http_get(item:string(dir, "/info.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL ) exit(0);
  if("<title>phpinfo()</title>" >< res)	
  	rep += dir + '/info.php\n';
}


if(rep != NULL)
{
 report = string("
The following files are calling the function phpinfo() which
disclose potentially sensitive information to the remote attacker : 
", rep, "

Solution : Delete them or restrict access to them
Risk factor : Low");

 security_warning(port:port, data:report);
}
