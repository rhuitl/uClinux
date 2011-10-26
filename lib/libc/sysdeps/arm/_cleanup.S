
	.text
	.align 2
	.global _cleanup
	.type _cleanup,%function

_cleanup:
	mov     ip, sp
	stmfd   sp!, {fp, ip, lr, pc}
	sub     fp, ip, #4
	ldmea   fp, {fp, sp, pc}
.Lfe1:
.size    _cleanup,.Lfe1-_cleanup

