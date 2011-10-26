#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is prone to a buffer overflow attack. 

Description :

The remote host is running MaxDB, a SAP-certified open-source database
supporting OLTP and OLAP. 

According to its version, the Web DBM component of MaxDB on the remote
host reportedly contains a buffer overflow that can be triggered by an
HTTP request containing a long database name.  An unauthenticated
remote attacker may be able to exploit this flaw to execute arbitrary
code on the affected host subject to the privileges of the 'wahttp'
process. 

See also :

http://www.symantec.com/enterprise/research/SYMSA-2006-009.txt
http://www.securityfocus.com/archive/1/444601/30/0/threaded

Solution :

Upgrade to Web DBM version 7.6.00.31 or later as that is reported to
fix the issue. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22309);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4305");
  script_bugtraq_id(19660);

  script_name(english:"Web DBM Remote Buffer Overflow Vulnerability");
  script_summary(english:"Gets version of Web DBM");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9999);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


if (report_paranoia < 2) exit(0);


port = get_http_port(default:9999);
if (!get_port_state(port)) exit(0);


# Make sure the banner indicates it's Web DBM.
banner = get_http_banner(port:port);
if (!banner || "Server: SAP-Internet-SapDb-Server" >!< banner) exit(0);


# Get the version number.
req = http_get(item:"/webdbm?Page=VERSION", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

ver = NULL;
build = NULL;
pat = '<td class="(dbmSTbvCellStd|dbmSTbvCellLast).*">([0-9][^<]+)</span';
matches = egrep(pattern:pat, string:res);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    m = eregmatch(pattern:pat, string:match);
    if (!isnull(m)) {
      if ("CellStd" >< m[1]) ver = chomp(m[2]);
      else if ("CellLast" >< m[1])
      {
        build = m[2];
        if (build =~ "^([0-9][0-9][0-9])-.*")
        {
          build = ereg_replace(pattern:"^([0-9][0-9][0-9])-.*", replace:"\1", string:build);
          build = int(build);
        }
      }
    }
  }
}
if (isnull(ver)) exit(0);
if (!isnull(build)) ver += "." + build;


# There's a problem if the version is under 7.6.00.31.
iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) < 7 ||
  (
    int(iver[0]) == 7 &&
    (
      int(iver[1]) < 6 ||
      (int(iver[1]) == 6 && int(iver[2]) == 0 && !isnull(iver[3]) && int(iver[3]) < 31)
    )
  )
)
{
  if (report_verbosity < 2)
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "According to its banner, Web DBM version ", ver, " is installed\n",
      "on the remote host.\n"
    );
  else report = desc;

  security_hole(port:port, data:report);
}

