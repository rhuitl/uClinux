#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote mail server is affected by multiple issues. 

Description :

GNU Mailutils is a collection of mail utilities, including an IMAP4
daemon, a POP3 daemon, and a very simple mail client. 

The remote host is running a version of GNU Mailutils containing
several critical flaws in its IMAP4 daemon and its mail client 'mail'. 
By exploiting these issues, a remote attacker can cause a denial of
service in the IMAP4 daemon and execute code remotely, either in the
context of a local user or the user executing the daemon process,
typically root. 

In addition, it may suffer from a SQL injection flaw if configured to
work with MySQL or Postgres.  An attacker may be able to exploit this
flaw to modify database queries when mailutils tries to authenticate a
user, leading to disclosure of sensitive information or modification
of data. 

See also :

http://www.idefense.com/application/poi/display?id=246&type=vulnerabilities
http://archives.neohapsis.com/archives/bugtraq/2005-07/0474.html

Solution : 

Upgrade to GNU Mailutils 0.6.90 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(18371);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1520", "CVE-2005-1521", "CVE-2005-1522", "CVE-2005-1523", "CVE-2005-1824");
  script_bugtraq_id(13763, 13764, 13765, 13766, 13870);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16854");
    script_xref(name:"OSVDB", value:"16855");
    script_xref(name:"OSVDB", value:"16856");
    script_xref(name:"OSVDB", value:"16857");
  }

  name["english"] = "GNU Mailutils <= 0.6 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in GNU Mailutils <= 0.6";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("find_service.nes");
  script_exclude_keys("pop3/false_pop3", "imap/false_imap");
  script_require_keys("pop3/login", "pop3/password", "imap/login", "imap/password");
  script_require_ports("Services/pop3", 110, "Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# Check the IMAP daemon.
port = get_kb_item("Services/imap");
if (!port) port = 143;
if (get_port_state(port) && !get_kb_item("imap/false_imap")) {
  # Establish a connection.
  tag = 0;
  soc = open_sock_tcp(port);
  if (soc) {
    # Read the banner.
    s = recv_line(socket:soc, length:1024);

    # If the banner suggests it's Mailutils...
    if ("* OK IMAP4rev1" >< s) {
      # If safe checks are enabled.
      if (safe_checks()) {
        # We'll try to log in as a user and get the version
        # from a CAPABILITIES command.
        user = get_kb_item("imap/login");
        pass = get_kb_item("imap/password");
        if (user && pass) {
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

            # If successful, issue an X-VERSION command.
            if (resp && resp =~ "OK") {
              ++tag;
              c = string("a", string(tag), " X-VERSION");
              send(socket:soc, data:string(c, "\r\n"));
              while (s = recv_line(socket:soc, length:1024)) {
                s = chomp(s);
                if (s =~ "^\* X-VERSION GNU imap4d .+ 0\.([0-5]|6(\)|\.[0-8]))") {
                  report = string(
                    desc["english"],
                    "\n\n",
                    "Plugin output :\n",
                    "\n",
                    "Note that Nessus has determined the vulnerability exists on the\n",
                    "remote host simply by looking at the version number of the IMAP4\n",
                    "daemon installed there.\n"
                  );
                  security_hole(port:port, data:report);
                }
                m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
                if (!isnull(m)) {
                  resp = m[1];
                  break;
                }
                resp = "";
            }
          }
        }
        else {
          if (log_verbosity > 1) debug_print("imap/login and/or imap/password are empty; skipped!", level:0);
        }
      }
      # Safe checks are disabled; let's try to exploit the format string flaw.
      else {
        # This should just crash the child process handling our connection.
        c = string("%n%n%n%n%n ", SCRIPT_NAME);
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

        # If we didn't get a response back, there's likely a problem.
        if (!strlen(s)) {
          security_hole(port);
          # nb: no need to close it.
          soc = NULL;
        }
      }

      # Be nice and logout if there's still a connection.
      if (soc) {
        ++tag;
        c = string("a", string(tag), " LOGOUT");
        send(socket:soc, data:string(c, "\r\n"));
        close(soc);
      }
    }
  }
}


# And check the POP3 daemon too.
port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (get_port_state(port) && !get_kb_item("pop3/false_pop3")) {
  # Establish a connection.
  soc = open_sock_tcp(port);
  if (soc) {
    s = recv_line(socket:soc, length:1024);

    # If the banner suggests it's Mailutils...
    if (s =~ "^\+OK POP3 Ready <[0-9]+\.[0-9]+@") {
      user = get_kb_item("pop3/login");
      pass = get_kb_item("pop3/password");

      # Try to log in.
      if (user && pass) {
        c = string("USER ", user);
        send(socket:soc, data:string(c, "\r\n"));
        while (s = recv_line(socket:soc, length:1024)) {
          s = chomp(s);
          m = eregmatch(pattern:"^(\+OK|-ERR)( |$)", string:s, icase:TRUE);
          if (!isnull(m)) {
            resp = m[1];
            break;
          }
          resp = "";
        }
        if (resp && resp =~ "OK") {
          c = string("PASS ", pass);
          send(socket:soc, data:string(c, "\r\n"));
          while (s = recv_line(socket:soc, length:1024)) {
            s = chomp(s);
            m = eregmatch(pattern:"^(\+OK|-ERR)( |$)", string:s, icase:TRUE);
            if (!isnull(m)) {
              resp = m[1];
              break;
            }
            resp = "";
          }
        }
        if (resp && resp =~ "ERR") {
          if (log_verbosity > 1) debug_print("can't login with supplied pop3 credentials; skipped!", level:0);
        }

        # The version is available through a CAPA command.
        if (resp && resp =~ "OK") {
          c = string("CAPA");
          send(socket:soc, data:string(c, "\r\n"));
          caps = "";
          s = recv_line(socket:soc, length:1024);
          s = chomp(s);
          if (s =~ "^\+OK( |$)") {
            while (s = recv_line(socket:soc, length:1024)) {
              s = chomp(s);
              if (s =~ "^\.$") break;
              caps = string(caps, s, "\n");
            }
          }
          # Check whether the version number indicates a problem.
          if (
            egrep(
              string:caps, 
              pattern:"IMPLEMENTATION GNU Mailutils 0\.([0-5]|6($|\.[0-8]))",
              icase:TRUE
            )
          ) {
            report = string(
              desc["english"],
              "\n\n",
              "Plugin output :\n",
              "\n",
              "Note that Nessus has determined the vulnerability exists on the\n",
              "remote host simply by looking at the version number of the POP3\n",
              "daemon installed there.\n"
            );
            security_hole(port:port, data:report);
          }
        }
      }
      else {
        if (log_verbosity > 1) debug_print("pop3/login and/or pop3/password are empty; skipped!", level:0);
      }
    }

    # Let's be nice and logout.
    c = "QUIT";
    send(socket:soc, data:string(c, "\r\n"));

    # And close the socket.
    close(soc);
  }
}
