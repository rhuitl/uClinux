#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


# NB: I define the script description here so I can later modify
#     it with the version number and install directory.
  desc["english"] = "
Synopsis :

The remote web server contains a webmail application written in PHP. 

Description :

This script detects whether the remote host is running BasiliX and
extracts version numbers and locations of any instances found. 

BasiliX is a webmail application based on PHP and IMAP and powered by
MySQL.

See also : 

http://sourceforge.net/projects/basilix/

Risk factor : 

None";


if (description) {
  script_id(14308);
  script_version("$Revision: 1.11 $");
 
  name["english"] = "BasiliX Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the presence of BasiliX";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  script_dependencies("http_version.nasl");
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


# Search for BasiliX in a couple of different locations.
if (thorough_tests) dirs = make_list("/basilix", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  url = string(dir, "/basilix.php");
  if (port == 443) url = string(url, "?is_ssl=1");

  # Get the page.
  req = string(
    "GET ",  url, " HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Cookie: BSX_TestCookie=yes\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  if ("BasiliX" >< res) {
    # Search for the version string in a couple of different places.
    #
    # - it's usually in the HTML title element.
    title = strstr(res, "<title>");
    if (title != NULL) {
      title = title - strstr(title,string("\n"));
      pat = "BasiliX (.+)</title>";
      ver = eregmatch(pattern:pat, string:title, icase:TRUE);
      if (ver != NULL) ver = ver[1];
    }
    # - otherwise, look at the "generator" meta tag.
    if (isnull(ver)) {
      generator = strstr(res, '<meta name="generator"');
      if (generator != NULL) {
        generator = generator - strstr(generator, string("\n"));
        pat = 'content="BasiliX (.+)"';
        ver = eregmatch(pattern:pat, string:generator, icase:TRUE);
        if (ver != NULL) ver = ver[1];
      }
    }
    # - last try, older versions include it in the copyright notice.
    if (isnull(ver)) {
      copyright = strstr(res, "BasiliX v");
      if (copyright != NULL) {
        copyright = copyright - strstr(copyright, string("\n"));
        pat = "BasiliX v(.+) -- &copy";
        ver = eregmatch(pattern:pat, string:copyright, icase:TRUE);
        if (ver != NULL) ver = ver[1];
      }
    }

    # Handle reporting
    if (!isnull(ver)) {
      set_kb_item(
        name:string("www/", port, "/basilix"), 
        value:string(ver, " under ", dir)
      );
      installations[dir] = ver;
      ++installs;
    }

    # Scan for multiple installations only if "Thorough Tests" is checked.
    if (installs && !thorough_tests) break;
  }
}


# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("BasiliX ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of BasiliX were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  desc = ereg_replace(
    string:desc["english"],
    pattern:"This script[^\.]+\.", 
    replace:info
  );
  security_note(port:port, data:desc);
}
