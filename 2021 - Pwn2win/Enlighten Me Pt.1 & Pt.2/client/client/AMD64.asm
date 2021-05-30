PUBLIC GetFlag
.CODE
GetFlag PROC
    mov     r8, rdx
    mov     eax,40000100h
    cpuid
    mov     dword ptr [r8], ebx
    mov     dword ptr [r8+4],ecx
    mov     dword ptr [r8+8],edx
	ret
GetFlag ENDP
END