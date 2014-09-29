BITS 32
section .text
_start:
    xor     eax,    eax
    inc     eax
    inc     eax
    inc     eax
    jmp     _start
