#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

 desc["english"] = "
Synopsis :

The remote web server is affected by an information disclosure issue.

Description :

It is possible to get the absolute path leading to the remote 
/cgi-bin directory by requesting a bogus cgi. This issue can be used to 
obtain OS and installation details.

See also :

http://archives.neohapsis.com/archives/bugtraq/1999-q4/0404.html

Solution : 

Contact your vendor for a patch.

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:L/Au:NR/C:C/I:N/A:N/B:N)";


if(description)
{
 script_id(10058);
 script_bugtraq_id(881);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0021");
 name["english"] = "Domino HTTP server exposes the set up of the filesystem";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "obtains absolute path to cgi-bin";
 
 script_summary(english:summary["english"]); 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl","www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Domino" >!< banner ) exit(0);

if(get_port_state(port))
{
  bogus = "just_a_test_ignore";
  url = string("/cgi-bin/", bogus);
  req = http_get(item:url, port:port);
  s = http_keepalive_send_recv(port:port, data:req);
  if (s == NULL) exit(0);

  line = egrep(pattern:url, string:s);
  if (line)
  {
    path = ereg_replace(pattern:string(".* ([^ ]+)/", bogus, ".*"), replace:"\1", string:line);
    if (path) path = ereg_replace(pattern:"^'(.+)", replace:"\1", string:path);
    if (path)
    {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "The physical path discovered is :\n",
        "\n",
        "  ", path
      );
      security_note(port:port, data:report);
    }
  }
}
