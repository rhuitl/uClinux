
int main() {
	//extern char **environ;
	//environ = envp;
	return 0;
}


/* We've got to provide an entry point that doesn't stuff around with a5 like
 * C routines tend to do.  We must also setup a5 from d5 which won't point to
 * this libraries data segment but from which it can be obtained.
 */
asm(	".globl lib_main\n\t"
	".type lib_main,@function\n"
	"lib_main:\n\t"
	"move.l %d5, %a5\n\t"
	"bra.w main\n"
	".L__end_lib_main__:\n\t"
	".size lib_main,.L__end_lib_main__-libmain"
);

