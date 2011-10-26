#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a Java application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running OpenCms, a Java-based content management
system. 

According to its banner, the version of OpenCms installed on the
remote host reportedly allows authenticated users to upload OpenCms
modules and database import/export files, download arbitrary files,
send messages to all users, and launch cross-site scripting attacks. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-July/048211.html
http://mail.opencms.org/pipermail/opencms-dev/2006q3/025016.html

Solution :

Upgrade to OpenCms version 6.2.2 or later. 

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22093);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(19174);

  script_name(english:"OpenCms < 6.22 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of OpenCms");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# Only run the plugin if we're being paranoid to avoid false-positives,
# which might arise because the software is open-source.
if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Check the version.
#
# nb: you can sometimes get the version from the Server response header,
#     but that won't work if Tomcat is used in conjunction with a webserver.
req = http_get(item:"/opencms/opencms/system/login/", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

if ("<title>Welcome to OpenCms" >< res)
{
  # Extract the version number.
  pat = "title>Welcome to OpenCms ([^<]+)</title";
  ver = NULL;
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  # There's a problem if the version is under 6.2.2.
  if (ver && ver =~ "^([0-5]\.|6\.([01]\.|2\.[01][^0-9]?))")
  {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "The version of OpenCms on the remote host was determined to be ", ver, ".\n"
    );
    security_warning(port:port, data:report);
  }
}
