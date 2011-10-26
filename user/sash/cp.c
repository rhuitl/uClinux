
void
do_cp(argc, argv)
	char	**argv;
{
	BOOL	dirflag;
	char	*srcname;
	char	*destname;
	char	*lastarg;

	lastarg = argv[argc - 1];

	dirflag = isadir(lastarg);

	if ((argc > 3) && !dirflag) {
		fprintf(stderr, "%s: not a directory\n", lastarg);
		return;
	}

	while (argc-- > 2) {
		destname = lastarg;
		if (dirflag)
			destname = buildname(destname, srcname);

		(void) copyfile(*++argv, destname, FALSE);
	}
}
