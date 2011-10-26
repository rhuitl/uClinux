#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

 desc["english"] = "
Synopsis :

The remote web server is affected by an information disclosure flaw. 

Description :

The remote host appears to be running Web+ Application Server. 

The version of Web+ installed on the remote host reveals the physical
path of the application when it receives a script file error. 

See also :

http://www.talentsoft.com/Issues/IssueDetail.wml?ID=WP197

Solution : 

Apply the vendor-supplied patch.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

if(description)
{
  script_id(12074);
  script_version ("$Revision: 1.6 $");

 name["english"] = "Talentsoft Web+ reveals install path";
 script_name(english:name["english"]);

 script_description(english:desc["english"]);

 summary["english"] = "Checks for Webplus install path disclosure";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 David Kyger");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
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
if(!get_port_state(port)) exit(0);

foreach dir (cgi_dirs()) {
  req = http_get(item:string(dir, "/webplus.exe?script=", SCRIPT_NAME), port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ("Web+ Error Message" >< buf)
  {
    if (report_verbosity > 0) {
      path = strstr(buf, " '");
      path = ereg_replace(pattern:" and.*$", replace:"",string:path);

      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        path
      );
    }
    else report = desc["english"];

    security_note(port:port, data:report);
  }
}
