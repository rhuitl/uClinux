#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
several issues. 

Description :

The remote host is running RunCMS, a content management system written
in PHP. 

The version of RunCMS installed on the remote host allows attackers to
overwrite arbitrary variables by passing them via a POST method and
may also suffer from several SQL injection vulnerabilities resulting
in, for example, disclosure of the admin password hash. 

See also : 

http://www.gulftech.org/?node=research&article_id=00094-08192005

Solution : 

Contact the vendor - the flaws reportedly were silently patched in
mid-July 2005. 

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:N/A:P/I:P/B:N)";


if (description) {
  script_id(19504);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2691", "CVE-2005-2692");
  script_bugtraq_id(14631, 14634);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18908");
    script_xref(name:"OSVDB", value:"18909");
    script_xref(name:"OSVDB", value:"18910");
    script_xref(name:"OSVDB", value:"18911");
    script_xref(name:"OSVDB", value:"18912");
  }

  name["english"] = "RunCMS <= 1.2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in RunCMS <= 1.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Check whether we're dealing with RunCMS / E-Xoops.
  req = http_get(item:string(dir, "/user.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  pat = "RUNCMS\.? *(.+) +&copy; 20[0-9][0-9] RUNCMS";
  matches = egrep(string:res, pattern:pat);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = chomp(ver[1]);
        break;
      }
    }

    # Try to exploit the variable-overwriting flaw to change the start page.
    #
    # nb: this only works if register_globals is off.
    postdata = string("xoopsConfig[startpage]=", SCRIPT_NAME);
    req = string(
      "POST ", dir, "/ HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we see a redirect involving our script name.
    if (string("Location: modules/", SCRIPT_NAME) >< res) {
      security_warning(port);
      exit(0);
    }

    # Fall back to testing the version number then.
    if (ver && ver =~ "^(0\..*|1\.(0.*|1A?|2))$") {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Note that Nessus has determined the vulnerability exists on the\n",
        "remote host simply by looking at the version number of RunCMS\n",
        "installed there.\n"
      );
      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
