; #########################################################################

      .586
      .model flat, stdcall
      option casemap :none   ; case sensitive

; #########################################################################
      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc
      include \masm32\include\comdlg32.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib
      includelib \masm32\lib\comdlg32.lib

; #########################################################################  
.data
    szDLL db "C:\masm32\projects\dll_injection\TestDll.dll",0
    szKernel32 db "kernel32.dll",0
    szLoadLibA db "LoadLibraryA",0
.code

InjectDLL proc inProcess:DWORD, inDLLPath:DWORD
LOCAL hProcess:DWORD
LOCAL pDLL:DWORD
LOCAL dwDLLSize:DWORD
LOCAL dwWritten:DWORD
LOCAL dwThreadID:DWORD

    invoke OpenProcess, PROCESS_ALL_ACCESS, FALSE, inProcess
    TEST EAX, EAX
    JE CodeFail
    MOV hProcess, EAX
    invoke lstrlenA, inDLLPath
    TEST EAX, EAX
    JE CodeFail
    INC EAX
    MOV dwDLLSize, EAX 
    invoke VirtualAllocEx, hProcess, NULL, dwDLLSize, MEM_COMMIT, PAGE_READWRITE
    TEST EAX, EAX
    JE CodeFail
    MOV pDLL, EAX
    invoke WriteProcessMemory, hProcess, pDLL, inDLLPath, dwDLLSize, ADDR dwWritten
    TEST EAX, EAX
    JE CodeFail
    invoke LoadLibraryA, OFFSET szKernel32
    invoke GetProcAddress, EAX, OFFSET szLoadLibA
    TEST EAX, EAX
    JE CodeFail
    MOV EBX, EAX ; got a compiler error if I just left EAX, so yeah..
    invoke CreateRemoteThread, hProcess, NULL, 0, EBX, pDLL, 0, ADDR dwThreadID
    TEST EAX, EAX
    JE CodeFail
    invoke CloseHandle, hProcess
    XOR EAX, EAX
    INC EAX
    JMP EndInject

CodeFail:
    XOR EAX, EAX
EndInject:
    MOV ESP, EBP ; yeah, still don't know why MASM creates a stack frame but doesn't restore it. Any ideas?
    POP EBP
    RETN 8
InjectDLL endp

start:
    invoke InjectDLL, 2420, OFFSET szDLL   

EndMain:
    RETN
end start
