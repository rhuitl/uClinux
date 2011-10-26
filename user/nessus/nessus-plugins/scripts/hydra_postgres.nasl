#TRUSTED aff63c3a051b5cc5002547b73d1259101789b4399a4542236e196dcc48812010aa7935c08e3608f4743819c4846eab4589058a2b15a54d88a09378d67a44ca3bd5bac8115b72d2821be31a8c1349c5b77bf2b6133f213e44751cded13398248b87ca7024d611206a5027a1338da218f99154f5bc0cbdd381922aed4a15e08a7423a4c06fcd3cbba0d6199decddf5b9616fd976de11ddab57d70c050192f55e58b3ada137b52b6649d1fcb9569e8c35eb029ae0accb0939775f93681c2baa2e8018239d37c75da62744e10e3f9a87e17d1cd7e63a25e59f609cb907c6154679513200c8703bf6840ead84523ef695abe008a8c133bd5c00294f2b35578a113737f33c454dcf5d521129f609b60d8d7f880399e4072b394058bde215d1cc2d5400ada75496c1863498b173b62b6f47638f4193e2784a377511ea91569bbdbfb81eb782452f976bf63524031d3b05481fef397e3d490c7d279582eed73eafe28e979ba83f0839733e1895cf18cde5d1edb5ed78df280df39f04769cfdf0e5d353aabfdab9ed62df7d56a56d697fb34d2b5bb58d2a4a862a0f4b33de59d7c1c4b22a5219924a6e645d7fc706ef56a84cc64ae5f28acb9b7799b829544d227768b721b081f58dff92163c87b5d1d506f7fbd567017b8ff0d045b4cecfda5632917f8244dfd4527b3d39a6f4cbd6cd6f228479e7e406671cea6bb97504b498ed7bd462
#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(18660);
 script_version ("1.1");
 name["english"] = "Hydra: Postgres";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find Postgres accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force Postgres authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_add_preference(name: "Database name (optional) : ", type: "entry", value: "");

 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/postgres", 5432);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl");
 exit(0);
}

#

thorough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< thorough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/postgres");
if (! port) port = 5432;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);
db = script_get_preference("Database name (optional) : ");

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
argv[i++] = "postgres";
if (db) argv[i++] = db;

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
    set_kb_item(name: 'Hydra/postgres/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following accounts on the Postgres server:\n' + report);
