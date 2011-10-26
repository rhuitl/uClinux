#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a content management system written in
PHP. 

Description :

The remote host is running Mambo Open Source or Mambo CMS, content
management systems written in PHP. 

See also : 

http://www.mamboserver.com/
http://www.miro.com.au/index.php?option=displaypage&Itemid=235&op=page

Risk factor :

None";


if (description) {
  script_id(17672);
  script_version("$Revision: 1.3 $");

  name["english"] = "Mambo Open Source / Mambo CMS Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for presence of Mambo Open Source / Mambo CMS";
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


# Search for Mambo.
#
# nb: Mambo has changed a lot over the years and can be configured to look
#     quite different. And getting an accurate version number requires
#     logging in as the administrator. Together, these make this script
#     rather convoluted. Suggestions for improvement welcome.
installs = 0;
foreach dir (cgi_dirs()) {
  # Try to pull up administrator page. As long as it exists, 
  # it's an easy way to distinguish which Mambo is installed.
  #
  # nb: a few webmasters rename the directory to improve security so
  #     we can't don't assume anything if the page isn't found.
  req = http_get(item:string(dir, "/administrator/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # The title should identify which type of Mambo the site is running.
  if (egrep(string:res, pattern:"^<title>.+ - Administration \[Mambo\]</title>$", icase:TRUE))
    type = "mos";
  else if (egrep(string:res, pattern:"^<TITLE>.+ \|\| Mambo CMS Admin</TITLE>$", icase:TRUE))
    type = "cms";

  # Sometimes the version number's embeded in the initial administrator 
  # page itself; if so, we're done!
  if (!isnull(type)) {
    pat = "<td .+Version *: *([^<]+)</td>";
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match, icase:TRUE);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
  }

  # If we don't know the version yet...
  if (isnull(ver)) {
    # Try to pull up main page.
    req = http_get(item:string(dir, "/index.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # If it exists...
    if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
      # If the type is still unknown...
      if (isnull(type)) {
        # It's Mambo CMS if...
        # the Generator meta tag says it is.
        if (egrep(string:res, pattern:"^X-Meta-Generator: Mambo CMS")) {
          type = "cms";
        }
        # else it's Mambo Open Source if...
        else if (
          # The mosvisitor cookie is present (only present if stats are enabled) or ...
          egrep(string:res, pattern:"^Set-Cookie: mosvisitor=1$") ||
          # A meta tag says its Mambo or...
          egrep(string:res, pattern:"^X-Meta-Description: Mambo( Open Source)? - the dynamic", icase:TRUE) ||
          egrep(string:res, pattern:"^X-Meta-Generator: Mambo (\(C\)|- Copyright)", icase:TRUE) ||
          # It has a "Powered by Mambo" logo.
          egrep(string:res, pattern:'<img src="images/[^"]+"[^>]* alt="Powered by Mambo', icase:TRUE)
        ) {
          type = "mos";
        }
        # else it might be Mambo Open Source if...
        else if (
          # There are relative links using Mambo components.
          egrep(string:res, pattern:'<a href="index2?\\.php\\?option=[^&]+&(Itemid|task)=', icase:TRUE) ||
          egrep(string:res, pattern:'<a href="index2?\\.php\\?option=com_(contact|content|frontpage|search|weblinks)', icase:TRUE) ||
          # There are absolute links using search-engine friendly format.
          egrep(
            string:res, 
            pattern:string(
              '<a href="https?://',
              "[^/]*",
              get_host_name(),
              "[^/]*",
              dir, "(content/(section|view)|component/option,com_)"
            ),
            icase:TRUE
          ) 
        ) {
          # So let's try some other checks to make sure.
          #
          # - mambojavascript.js exists in Mambo Open Source 4.5+
          req = http_get(item:string(dir, "/includes/js/mambojavascript.js"), port:port);
          res2 = http_keepalive_send_recv(port:port, data:req);
          if (res2 == NULL) exit(0);
          if (egrep(string:res2, pattern:"^\* @package Mambo(Open Source|_[0-9])", icase:TRUE)) {
            type = "mos";
          }
          else {
            # - mambositeserver.gif exists in Mambo Open Source 4.0.x
            #   aka Mambo Site Server.
            req = http_get(item:string(dir, "/images/stories/mambositeserver.gif"), port:port);
            res2 = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
            if (res2 == NULL) exit(0);
            if (res2[0] == 'G' && res2[1] == 'I' && res2[2] == 'F') {
              type = "mos";
            }
          }
        }
      }

      # If we know the type now, try to get the version number.
      if (!isnull(type)) {
        # Sometimes the version number is part of the Generator meta tag.
        pat = '^X-Meta-Generator: Mambo (CMS|Site Server|Open Source) (.+)';
        matches = egrep(pattern:pat, string:res, icase:TRUE);
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver)) {
            ver = ver[2];
            break;
          }
        }
      }
    }
  }

  # If the type is known, update the KB.
  if (!isnull(type)) {
    # If we couldn't find the version number, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";

    set_kb_item(
      # nb: keys are identified by "mambo_cms" or "mambo_mos" at the end.
      name:string("www/", port, "/mambo_", type),
      value:string(ver, " under ", dir)
    );
    types[dir] = type;
    installations[dir] = ver;
    ++installs;

    # Scan for multiple installations only if "Thorough Tests" is checked.
    if (!thorough_tests) break;
  }
}

# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    if (types[dir] == "cms") type = "CMS";
    else if (types[dir] == "mos") type = "Open Source";
    else type = "";

    if (ver == "unknown") {
      info = string(
        "An unknown version of Mambo ", type, " was detected on the\n",
        "remote host under the path ", dir, "."
      );
    }
    else {
      info = string(
        "Mambo ", type, " ", ver, " was detected on the remote host\n",
        "under the path ", dir, "."
      );
    }
  }
  else {
    info = string(
      "Multiple instances of Mambo were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      if (types[dir] == "cms") type = "CMS";
      else if (types[dir] == "mos") type = "Open Source";
      else type = "";

      info = info + string("    Mambo ", type, " ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  report = string(
    desc["english"],
    "\n\n",
    "Plugin output :\n",
    "\n",
    info
  );
  security_note(port:port, data:report);
}
