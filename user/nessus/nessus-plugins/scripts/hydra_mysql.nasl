#TRUSTED 281ba3f3dd5f87f35205246c2dd250c2fa84caf85f08789791457bb3403c5342df4a9c91ae4127777eb924691c6c96c4fbafcd8b68a2890f724c24126c5195408e44c1e4d724c85f7e12884acdca882356f0d87df304543569fd04476f0ab1a6167f9a95a918ef96fb415763479bf37c15b08e6a3e0bc9e68f839a9592e2186a4a71701a94b9988116d23ac79583e8a836e245bd166330666e40b1cf4cfaa91a5ef5a007d9efe697016c8aa52b73c2883db0030728c92dcdec8082da9a406b3ddbf2f9ead651b864b346277b64aea78fc6324902b68c90bfa868b3a5b06841a480d8c915807833fb9969552b548379267aa00ab84ef7b9689de30da3e25c9c26bc84390add094ca4c4ebff1f6aed43bb9a43bb5993a236a06303425267df8ae17844b483542b2096882b41cca3aa92768437cf880130b1fe1615536c9279b9cdd5ac6f25eaa1cfe0c18056788c58e044706a1de3b76b197e5efe61d984c59f25574d5439e3730f5de561a8448f99634bd7afa9bb59937c7d45708f9fc12697daab5921bbf03314d0d5d6091697343138035bfc2533b41e9e8af5dad8c674f6cd1c3e2cf71aaf30494b4d5746a82ad52d8661ee029710f631190c0184bef3a182806104633ac020ba8a58fc872e196300160f98980c55522356fcb5c0b269da844d7c05452e1a08328134cec630cb33cd75aae11e87f57be66ac856def75d3281
#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(18661);
 script_version ("1.1");
 name["english"] = "Hydra: MySQL";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find MySQL accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force MySQL authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);

 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/mysql", 3306);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl", "mysql_version.nasl");
 exit(0);
}

#

thorough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< thorough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/mysql");
if (! port) port = 3306;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "mysql";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/mysql/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following accounts on the MySQL server:\n' + report);
