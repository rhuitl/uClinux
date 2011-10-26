#
# (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote fax server fails to properly validate passwords. 

Description :

The remote host is running HylaFAX, a fax / pager server application
for Linux / unix. 

The version of HylaFAX installed on the remote host does not check
passwords when authenticating users via hfaxd, its fax server.  An
attacker can exploit this issue to bypass authentication using a valid
username and gain access to the system. 

See also :

http://bugs.hylafax.org/bugzilla/show_bug.cgi?id=682
http://www.hylafax.org/content/HylaFAX_4.2.4_release

Solution : 

Rebuild HylaFAX with PAM support or upgrade to HylaFAX version 4.2.4
or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20387);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3538");
  script_bugtraq_id(16150);
 
  script_name(english:"HylaFAX hfaxd Password Check Vulnerability");
  script_summary(english:"Checks for password check vulnerability in HylaFAX hfaxd");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/hylafax", 4559);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/hylafax");
if (!port) port = 4559;
if (!get_port_state(port)) exit(0);


# Try to exploit the flaw.
soc = open_sock_tcp(port);
if (soc) {
  foreach user (make_list("fax", "guest", "root")) {
    # There's a problem if we can log in using a random password.
    pass = rand_str();
    if (ftp_authenticate(socket:soc, user:user, pass:pass)) {
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus was able to log in using the following credentials :\n",
          "\n",
          "  User:     ", user, "\n",
          "  Password: ", pass, "\n"
        );

      security_warning(port:port, data:report);
      exit(0);
    }
  }

  ftp_close(socket:soc);
}
