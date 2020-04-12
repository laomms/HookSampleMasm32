.386
.model flat, stdcall
option casemap:none

include windows.inc
include msvcrt.inc
include kernel32.inc

includelib kernel32.lib
includelib msvcrt.lib

.data
greet	db	"enter file name: ",0
sgreet	db	"%s",0
dreet	db	"enter DLL name: ",0
dgreet	db	"%s",0
apiname	db	"LoadLibraryA",0
dllname	db	"kernel32.dll",0

.data?
processinfo	 PROCESS_INFORMATION <>
startupinfo	STARTUPINFO <>
fname	db	20	dup(?)
dname	db	20	dup(?)
dllLen	dd	?
mAddr	dd	?
vpointer	dd	?
lpAddr	dd	?


.code
start:

invoke crt_printf,addr greet
invoke crt_scanf,addr sgreet,addr fname
invoke crt_printf,addr dreet
invoke crt_scanf,addr dgreet,addr dname
invoke LoadLibrary, addr dllname
ov mAddr,eax
invoke GetProcAddress,mAddr,addr apiname
mov lpAddr,eax

;create process in suspended state
invoke CreateProcess,addr fname,0,0,0,0,CREATE_SUSPENDED,0,0,addr startupinfo,addr processinfo
invoke crt_strlen,addr dname
mov dllLen,eax

; Allocate the space into the newly created process
invoke VirtualAllocEx,processinfo.hProcess,NULL,dllLen,MEM_COMMIT,PAGE_EXECUTE_READWRITE
mov vpointer,eax

; Write DLL name into the allocated space
invoke WriteProcessMemory,processinfo.hProcess,vpointer,addr dname,dllLen,NULL

; Execute the LoadLibrary function using CreateRemoteThread into the previously created process
invoke CreateRemoteThread,processinfo.hProcess,NULL,0,lpAddr,vpointer,0,NULL
invoke Sleep,1000d

; Finally resume the process main thread.
invoke ResumeThread,processinfo.hThread
xor eax,eax
invoke ExitProcess,eax

end start
