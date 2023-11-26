section .text
    global addIndexToTLSArray

addIndexToTLSArray:

    push rdx
    mov rdx, [gs:58h]
    mov rcx, qword [rdx+rcx*4]
    pop rdx
    mov rdx, rcx
    ret
