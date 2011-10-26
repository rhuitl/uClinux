# Written by Gareth Phillips - SensePost PTY ltd
# www.sensepost.com
#

desc["english"] = "
Synopsis :

The remote web server contains a 'sitemap.xml' file. 

Description :

The Sitemap Protocol allows you to inform search engines about URLs on
your websites that are available for crawling.  In its simplest form,
a Sitemap is an XML file that lists URLs for a site. 

It has been discovered that many site owners are not building their
Sitemaps through spidering, but by scripted runs on their web root
directory structures.  If this is the case, an attacker may be able to
use sitemaps to to enumerate all files and directories in the
webserver root. 

See also :

http://www.quietmove.com/blog/google-sitemap-directory-enumeration-0day/
https://www.google.com/webmasters/sitemaps/docs/en/protocol.html


Solution :

Site owners should be wary of automatically generating sitemap.xml
files, and admins should review the contents of there sitemap.xml file
for sensitive material. 

Risk factor :

None";

if (description) {
script_id(22867);
script_version("$Revision: 1.2 $");

name["english"] = "Sitemap.xml File and Directory Enumeration";
script_name(english:name["english"]);

script_description(english:desc["english"]);

summary["english"] = "Checks for a web server's sitemap.xml";
script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2006 SensePost");

script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);

exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

dirs = get_kb_list(string("www/", port, "content/directories"));
if(isnull(dirs))dirs = make_list("", "/sitemap", "/map"); # Just some Defaults
dirs = make_list(dirs, cgi_dirs());

info = '';
foreach d (dirs)
{
  # Trying to retrieve the file.
  url = d+"/sitemap.xml";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if ("?xml version" >< res)
  {
    pat = "<loc>(.+)</loc>";
    matches = egrep(string:res, pattern:pat);
    if (matches)
    {
      info += '\n' + '  ' + url + '\n';

      foreach match (split(matches)) {
        match = chomp(match);
        loc = eregmatch(pattern:pat, string:match);
        if (!isnull(loc)) 
          info += '    <loc>' + loc[1] + '</loc>\n';
      }
    }
  }
  if (info && !thorough_tests) break;
}



if (info)
{
  report = string(
    desc["english"],
    "\n\n",
    "Plugin output : \n",
    "\n",
    "Nessus gathered the following information from Sitemaps :\n",
    info
  );
  security_note(port:port, data:report);
}
