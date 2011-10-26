#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server itself is prone to cross-site scripting attacks. 

Description :

The remote host is running a web server that fails to adequately
sanitize request strings of Javascript.  By exploiting this flaw, an
attacker may be able to cause arbitrary HTML and script code to be
executed in a user's browser within the security context of the affected
site. 

Solution : 

Contact the vendor for a patch or upgrade.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description) {
  script_id(10815);
  script_version("$Revision: 1.45 $");

  script_bugtraq_id(5305, 7344, 7353, 8037, 14473, 17408);
  script_cve_id("CVE-2002-1060", "CVE-2005-2453", "CVE-2006-1681");

  name["english"] = "Web Server Generic Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for generic cross-site scripting vulnerability in a web server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


file = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_");
exts = make_list(
  "",
  "asp",
  "cfm",
  "html",
  "jsp",
  "php",
  "php3",
  "phtml",
  "shtml"
);
# nb: this isn't valid Javascript; still, it can be used to 
#     suggest whether the flaw exists.
xss = "<script>" + SCRIPT_NAME + "</script>";


foreach ext (exts) {
  if (ext) urls = make_list(string("/", file, ".", ext, "?", xss));
  else
    urls = make_list(
      # nb: does server check "filenames" for Javascript?
      string("/", xss),
      xss,
      # nb: how about just the request string?
      string("/?", xss)
    );

  foreach url (urls) {
    # Try to exploit the flaw.
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    if (xss >< res) {
      if (report_verbosity > 0) {
        desc["english"] += '\n\nPlugin output :\n\n' + 
          'The request string used to detect this flaw was:\n' +
          '\n' +
          "  " + url + '\n';
      }
      set_kb_item(name:string("www/", port, "/generic_xss"), value:TRUE);
      security_note(port:port, data:desc["english"]);

      exit(0);
    }
  }
}
