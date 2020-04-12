.386
.model flat,stdcall
option casemap:none

include windows.inc
include kernel32.inc
include msvcrt.inc
include user32.inc


includelib kernel32.lib
includelib msvcrt.lib
includelib user32.lib


.data

tszMsg		db	"Hello from Hooking Function",0
userDll		db	"user32.dll",0
msgapi		db	"MessageBoxA",0


.data?
oByte1	dd	?
oByte2	dd	?
userAddr	dd	?
msgAddr	dd	?
nOldProt	dd	?

.code 
LibMain proc hInstDLL:DWORD, reason:DWORD, unused:DWORD
 .if reason == DLL_PROCESS_ATTACH 
	invoke LoadLibrary,addr userDll
	mov userAddr,eax
    
	; Get MessageBoxA address from user32.dll
	invoke GetProcAddress,userAddr,addr msgapi
	mov msgAddr, eax
	
    ; Set permission to write at the MessageBoxA address
	invoke VirtualProtect,msgAddr,20d,PAGE_EXECUTE_READWRITE,OFFSET nOldProt
	
    ; Store first 8 byte from the MessageBoxA address
	mov eax,msgAddr
	mov ebx, dword ptr DS:[eax]
	mov oByte1,ebx
	mov ebx, dword ptr DS:[eax+4]
	mov oByte2,ebx

	patchlmessagebox:
		; Write JMP MyHandler (pointer) at MessageBoxA address
		mov byte ptr DS:[eax],0E9h
		; move MyHandler address into ecx
		mov ecx,MyHandler
		add eax,5
		sub ecx,eax
		sub eax,4
		mov dword ptr ds:[eax],ecx
		
    .elseif reason == DLL_PROCESS_DETACH 
    .elseif reason == DLL_THREAD_ATTACH
    .elseif reason == DLL_THREAD_DETACH
    .endif
    ret
LibMain endp


MyHandler proc
		pusha
		xor eax,eax
		mov eax,msgAddr
		
        ; change the lpText parameter to MessageBoxA with our text 
		mov dword ptr ss:[esp+028h],offset tszMsg
		
        ; Restore the bytes at MessageBoxA address
		mov ebx,oByte1
		mov dword ptr ds:[eax],ebx
		mov ebx,oByte2
		mov dword ptr ds:[eax+4],ebx
		
        ; Restore all registers
		popa
		
        ;jump to MessageBoxA address (Transfer control back to MessageBoxA)
		jmp msgAddr
MyHandler endp

end LibMain
