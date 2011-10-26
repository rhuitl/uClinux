#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The remote web server contains a bulletin-board system written in PHP. 

Description :

This script detects whether the remote host is running phpBB and
extracts version numbers and locations of any instances found. 

phpBB is a bulletin-board system written in PHP. 

See also : 

http://www.phpbb.com/

Risk factor : 

None";


if(description)
{
 script_id(15779);

 script_version("$Revision: 1.10 $");
 name["english"] = "phpBB Detection";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Check for phpBB version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 - 2006 Tenable Network Security");
 
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/phpbb", "/phpBB", "/phpBB2", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If phpBB's "Powered by" banner is found...
  if (egrep(pattern:"Powered by <[^>]+>phpBB</a> .*&copy; 2001.* phpBB Group", string:res)) {
    # Try to grab the version number from the main page.
    #
    # nb: this won't generally work for versions starting with 2.0.12 but
    #     since we already have index.php we'll try that first.
    pat = "Powered by.*phpBB</a> ([0-9].+) &copy;";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }

    # If still unsuccessful, try to grab it from the changelog.
    if (isnull(ver)) {
      req = http_get(item:dir + "/docs/CHANGELOG.html", port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      pat = "<title>phpBB +(.+) +:: Changelog</title>";
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }

      # Try to adjust for an unspecified version number in the title.
      if (ver == "2.0.x") {
        ver = NULL;

        pat = ">Changes since (.+)</a></li>";
        matches = egrep(pattern:pat, string:res);
        foreach match (split(matches)) {
          match = chomp(match);
          prev_ver = eregmatch(pattern:pat, string:match);
          if (!isnull(prev_ver)) {
            prev_ver = prev_ver[1];
            if (prev_ver == "2.0.20") ver = "2.0.21";
            else if (prev_ver == "2.0.19") ver = "2.0.20";
            else if (prev_ver == "2.0.18") ver = "2.0.19";
            else if (prev_ver == "2.0.17") ver = "2.0.18";
            else if (prev_ver == "2.0.16") ver = "2.0.17";
            else if (prev_ver == "2.0.15") ver = "2.0.16";

            break;
          }
        }
      }
    }

    # Generate report and update KB.
    #
    # nb: even if we don't know the version number, it's still useful 
    #     to know that it's installed and where.
    if (dir == "") dir = "/";

    if (isnull(ver)) {
      ver = "unknown";
      info = string(
        "An unknown version of phpBB is installed on the remote host\n",
        "under '", dir, "'.\n"
      );
    }
    else {
      info = string(
        "phpBB version ", ver, " is installed on the remote host\n",
        "under '", dir, "'.\n"
      );
    }

    report = string(
      desc["english"],
      "\n\n",
      "Plugin output :\n",
      "\n",
      info
    );

    security_note(data:report, port:port);
    set_kb_item(
      name:string("www/", port, "/phpBB"),
      value:string(ver, " under ", dir)
    );

    if (!thorough_tests) exit(0);
  }
}
