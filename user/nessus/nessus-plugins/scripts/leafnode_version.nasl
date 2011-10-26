#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL...
#

if(description)
{
 script_id(11517);
 script_cve_id("CVE-2002-1661");
 script_bugtraq_id(6490);
 script_version ("$Revision: 1.11 $");

 name["english"] = "Leafnode denials of service";
 script_name(english:name["english"]);
 # Generic description is not used in security_hole calls
 desc["english"] = "
According to its version number that Nessus read in the banner, 
your Leafnode NNTP server is vulnerable to a denial of service.

** Note that Nessus did not check the actual flaw and
** relied upon the banner, so this may be a false positive.

Risk factor : Medium
Solution: upgrade it to 1.9.48 or later";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check Leafnode version number for flaws";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("nntpserver_detect.nasl");
 script_require_ports("Services/nntp", 119);

 exit(0);
}

#

port = get_kb_item("Services/nntp");
if (! port) port = 119;
if (! get_port_state(port)) exit(0);

k = string("nntp/banner/", port);
b = get_kb_item(k);
if (! b)
{
  soc = open_sock_tcp(port);
  if (! soc) exit(0);
  b = recv_line(socket: soc, length: 2048);
  close(soc);
}

# Example of banner:
# 200 Leafnode NNTP Daemon, version 1.9.32.rel running at localhost (my fqdn: www.nessus.org)

if ("Leafnode" >< b)
{
  if (ereg(string: b, pattern: "version +1\.9\.2[0-9]"))
  {
    report = "
According to its version number that Nessus read in the banner, 
your Leafnode NNTP server is vulnerable to a denial of service:
it may go into an infinite loop with 100% CPU use when an article 
that has been crossposted to several groups, one of which is the 
prefix of another, and when this article is then requested by its 
Message-ID.

** Note that Nessus did not check the actual flaw and
** relied upon the banner, so this may be a false positive.

Risk factor : Medium
Solution: upgrade it to 1.9.48 or later";
    security_warning(port: port, data: report);
  }
  else if (ereg(string: b, pattern: "version +1\.9\.([3-9]|[1-3][0-9]|4[0-7])[^0-9]"))
  {
    report="
According to its version number that Nessus read in the banner, 
your Leafnode NNTP server is vulnerable to a denial of service:
it may hangs without consuming CPU while waiting for data that 
never come.

** Note that Nessus did not check the actual flaw and
** relied upon the banner, so this may be a false positive.

Risk factor : Low
Solution: upgrade it to 1.9.48 or later";
     security_warning(port: port, data: report);
  }

  # Better double check this old version, although this is not strictly
  # a _security_ bug
  if (ereg(string: b, pattern: "version +1\.9\.19"))
  {
    report="
According to its version number (1.9.19) that Nessus read in 
the banner, your Leafnode NNTP server has some critical 
bugs and should not be used: it can corrupt parts of its news
spool under certain circumstances.

** Note that Nessus did not check the actual flaw and
** relied upon the banner, so this may be a false positive.

Risk factor : Medium
Solution: upgrade it to 1.9.48 or later";
     security_warning(port: port, data: report);
  }
}
