
.text

setbig:
        mrc     p15, 0, r0, c1, c0, 0
        orr     r0, r0, #0x00001000
        orr     r0, r0, #0x0000000c
        mcr     p15, 0, r0, c1, c0, 0

        mrc  p15,0,r0,c2,c0,0
        mov  r0,r0
        sub  pc,pc,#4

	mcr	p15, 0, r1, c7, c5, 0

        mrc  p15,0,r0,c2,c0,0
        mov  r0,r0
        sub  pc,pc,#4


