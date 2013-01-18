;
; Tech Cleaner
; Copyright Anthony Kosednar 2013
;
; This work is licensed under the Creative Commons Attribution-NonCommercial 3.0 Unported License. 
; To view a copy of this license, visit http://creativecommons.org/licenses/by-nc/3.0/ 
; or send a letter to Creative Commons, 444 Castro Street, Suite 900, Mountain View, California, 94041, USA.

;;;;;;;;;;;;;;;;;;;;;
; Setup Script
;;;;;;;;;;;;;;;;;;;;;


#NoTrayIcon
#RequireAdmin
#include "CompInfo.au3"
#include "Zip.au3"
#include <Array.au3>
#Include <process.au3>
#include <Inet.au3>
#include <File.au3>
#include "WinHttp.au3"

Global $version = 1.0
Global $updateurl = "https://raw.github.com/akosednar/TechCleaner/master/"
Global $criticalalert = 0 ; Start the counter at 0.
Global $currentstep = 0 ; Current Step

HttpSetProxy(1) ; Prevent Malicious Proxies

;;;;;;;;;;;;;;;;;;;;;
; Define Some Fucntions
;;;;;;;;;;;;;;;;;;;;;

Func _initial()
	DirCreate("c:\techcleaner\apps\")
	DirCreate("c:\techcleaner\reg-backup\")
	DirCreate("c:\techcleaner\logs\")
EndFunc


Func _housekeeping()
	DirRemove("c:\techcleaner\apps\",1)
	DirCreate("c:\techcleaner\apps\")
	IniWrite("C:\techcleaner\info.ini", "run", "finished", "no")
	IniWrite("C:\techcleaner\info.ini", "run", "last", "0")
EndFunc

Func _record($message,$priority=0)
	Local $test = false	
	
	
	$array = StringRegExp($message, '<(?i)step>(.*?)</(?i)step>', 2)
	For $i = 0 To UBound($array) - 1
		$return =  $array[$i]
		$test = true
	Next

	if $priority == 1 Then
		_FileWriteLog($alert, $message)
		_FileWriteLog($alerthistory, $message)
	Else
		_FileWriteLog($general, $message)
	EndIf

	If $test == true Then
		$currentstep = $return
		ProgressSet(100*(0.25*($return-1)), "Preforming Step " & $return & " / 4")
		ConsoleWrite ("Reg Return: " & $return & @CRLF)
		$message = "~ Step " & $return
	Else
		; We only write non-priority/threat level messages to progress view
		If $priority <> 1 Then
			ProgressSet(100*(0.25*($currentstep-1)),"Preforming Step " & $currentstep & " / 4" & @CRLF & @CRLF& $message)
		EndIf
	Endif

	_FileWriteLog($complete, $message)
	ConsoleWrite ($message & @CRLF)
EndFunc

Func _TimeGetStamp()
	Local $av_Time
	$av_Time = DllCall('CrtDll.dll', 'long:cdecl', 'time', 'ptr', 0)
	If @error Then
		SetError(99)
		Return False
	EndIf
	Return $av_Time[0]
EndFunc

Func _iereset()
   RunWait("RunDll32.exe inetcpl.cpl,ClearMyTracksByProcess 4351")
EndFunc

Func _regbckup()
	    $time = _TimeGetStamp()
	    _record("Backing up Registry - c:\techcleaner\reg-backup\backup-" & $time & ".reg",1)
	    _RunDos("Regedit /e c:\techcleaner\reg-backup\backup-" & $time & ".reg")
EndFunc

Func _killproxy()
	 RegWrite("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings","ProxyEnable", "REG_DWORD", "0")
EndFunc

Func _regchk()
	Local $regloc[5] ; Define Registry Locations to check
	$regloc[0] = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
	$regloc[1] = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
	$regloc[2] = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
	$regloc[3] = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
	$regloc[4] = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"

	Local $RegKeyWhitelist[11] ; Create Registry Whitelist array
	$RegKeyWhitelist[0] = "(Default)"
	$RegKeyWhitelist[1] = "Apoint" ; apls pointing driver
	$RegKeyWhitelist[2] = "snp2uvc" ; sonix sound 
	$RegKeyWhitelist[3] = "IgfxTray" ; intel graphics helper
	$RegKeyWhitelist[4] = "AESTFLtr" ; andrea audio driver
	$RegKeyWhitelist[5] = "RTHDCPL" ; realtek audio manager
	$RegKeyWhitelist[6] = "SynTPEnh" ; synaptics touchpad
	$RegKeyWhitelist[7] = "hkcmd" ; intel graphics helper
	$RegKeyWhitelist[8] = "igfxpers" ; intel common user interface module
	$RegKeyWhitelist[9] = "Persistence"
	$RegKeyWhitelist[10] = "Google Update" ; Google Updater
	; sort the array to be able to do a binary search
	_ArraySort($RegKeyWhitelist)

	For $z = 0 to UBound($regloc) - 1
	   For $i = 1 to 100
	   $var = RegEnumVal($regloc[$z], $i)
	   $reg_name = True 
	   $reg_value = True
	   if @error <> 0 Then ContinueLoop
		  ; Check key name
		  Local $iKeyIndex = _ArrayBinarySearch($RegKeyWhitelist,$var)
		  If Not @error Then
			 $reg_name = False
		  EndIf
		  
		  ; Check key name
		  Local $iKeyIndex = _ArrayBinarySearch($RegKeyWhitelist,$var & "exe")
		  If Not @error Then
			 $reg_name = False
		  EndIf
		  
		  ; Check key value
		  Local $iKeyIndex = _ArrayBinarySearch($RegKeyWhitelist,RegRead($regloc[$z], $var))
		  If Not @error Then
			 $reg_value = False
		  EndIf
		  
		   ; Check key value
		  Local $iKeyIndex = _ArrayBinarySearch($RegKeyWhitelist,RegRead($regloc[$z], $var) & "exe")
		  If Not @error Then
			 $reg_value = False
		  EndIf

		  If $reg_name == True AND $reg_value == True Then
			; Detect If Already Disabled
			$a = RegRead ($regloc[$z],$var)
			$a = StringSplit($a, "")
			If $a[1] <> ";" Then
				_record("Detected Non-Whitelisted Registry Entry! -" & $var & "- (" &RegRead ($regloc[$z],$var) & ")" & " (Killing) ",1)
				$criticalalert = $criticalalert + 1
				RegWrite($regloc[$z], $var, "REG_SZ", ";;" & RegRead ($regloc[$z],$var) & ";;")
			EndIf
		  EndIf
	   Next
	Next
EndFunc

Func _prockill()
	Local $pr = ProcessList()
	Local $RegProcWhitelist[47] ; Create Process Whitelist array
	$RegProcWhitelist[0] = "[System Process]"
	$RegProcWhitelist[1] = "System"
	$RegProcWhitelist[2] = "alg.exe"
	$RegProcWhitelist[3] = "csrss.exe"
	$RegProcWhitelist[4] = "explorer.exe"
	$RegProcWhitelist[5] = "lsass.exe"
	$RegProcWhitelist[6] = "services.exe"
	$RegProcWhitelist[7] = "smss.exe"
	$RegProcWhitelist[8] = "svchost.exe"
	$RegProcWhitelist[9] = "winlogon.exe"
	$RegProcWhitelist[10] = "taskmgr.exe"
	$RegProcWhitelist[11] = "userinit.exe"
	$RegProcWhitelist[12] = "AutoIt3.exe"
	$RegProcWhitelist[13] = "LogonUI.exe"
	$RegProcWhitelist[14] = "System Idle Process"
	$RegProcWhitelist[15] = "taskhost.exe"
	$RegProcWhitelist[16] = "VSSVC.exe"
	$RegProcWhitelist[17] = "wininit.exe"
	$RegProcWhitelist[18] = "winlogon.exe"
	$RegProcWhitelist[19] = "sppsvc.exe"
	$RegProcWhitelist[20] = "svchost.exe"
	$RegProcWhitelist[21] = "XenDpriv.exe"
	$RegProcWhitelist[22] = "WmiPrvSE.exe"
	$RegProcWhitelist[23] = "lsm.exe"
	$RegProcWhitelist[24] = "SMSvcHost.exe"
	$RegProcWhitelist[25] = "msdtc.exe"
	$RegProcWhitelist[26] = "rdpclip.exe"
	$RegProcWhitelist[27] = "dwm.exe"
	$RegProcWhitelist[28] = "SciTE.exe"
	$RegProcWhitelist[29] = "XenGuestAgent.exe"
	$RegProcWhitelist[30] = "audiodg.exe"
	$RegProcWhitelist[30] = "spoolsv.exe"
	$RegProcWhitelist[31] = "TrustedInstaller.exe"
	$RegProcWhitelist[33] = "PrintIsolationHost.exe"
	$RegProcWhitelist[34] = "Oobe.exe"
	$RegProcWhitelist[35] = "LMIGuardian.exe"
	$RegProcWhitelist[36] = "LMIRTechConsole.exe"
	$RegProcWhitelist[37] = "Support-LogMeInRescue.exe"
	$RegProcWhitelist[38] = "lmi_rescue.exe"
	$RegProcWhitelist[39] = "regedit.exe"
	$RegProcWhitelist[40] = "chrome.exe"
	$RegProcWhitelist[41] = "iexplorer.exe"
	$RegProcWhitelist[42] = "firefox.exe"
    	$RegProcWhitelist[43] = "Autoit_Studio.exe"
    	$RegProcWhitelist[44] = "MsMpEng.exe"
    	$RegProcWhitelist[45] = "msseces.exe"
	$RegProcWhitelist[46] = @ScriptName
	_ArraySort($RegProcWhitelist)
	For $i = 1 To $pr[0][0]
		  Local $iKeyIndex = _ArrayBinarySearch($RegProcWhitelist,$pr[$i][0])
		  If @error Then
			$criticalalert = $criticalalert + 1
			_record("Detected Non-Whitelisted Process! " & $pr[$i][0] & " (Killing) ",1)		        
			ProcessClose($pr[$i][0])
		  EndIf
		Sleep(500)
	Next
EndFunc

Func _srvchk()
	Dim $Services
	_ComputerGetServices($Services, "Running")

	If @error Then

		$error = @error

		$extended = @extended

		Switch $extended

			Case 1

				_ErrorMsg($ERR_NO_INFO)

			Case 2

				_ErrorMsg($ERR_NOT_OBJ)

		EndSwitch

	EndIf



	For $i = 1 To $Services[0][0] Step 1
		If  $Services[$i][4] == "" OR $Services[$i][4] == " " Then
			_record("Detected Possible Rouge Service! " & " - " & $Services[$i][7] & " - (" & $Services[$i][10] & ")",1)
			$criticalalert = $criticalalert + 1	
		EndIf

	Next
EndFunc

Func _ccleaner()
	If @OSARCH = "x86" Then
	    $program = "CCleaner.exe"
	Else
	    $program = "CCleaner64.exe" ; run 64 bit if the os is 64 bit
	EndIf
	_record("Running " & $program)
	run("c:\techcleaner\apps\ccleaner\" & $program &" /AUTO")
	_record("Finished " & $program)
EndFunc

Func _defraggler()
	If @OSARCH = "x86" Then
	    $program = "df.exe"
	Else
	    $program = "df64.exe" ; run 64 bit if the os is 64 bit
	EndIf
	_record("Running " & $program)
	run("c:\techcleaner\apps\defraggler\" & $program &" C:\")
	_record("Finished " & $program)
EndFunc

Func _msessentials()
	; xp: http://mse.dlservice.microsoft.com/download/A/3/8/A38FFBF2-1122-48B4-AF60-E44F6DC28BD8/enus/x86/mseinstall.exe
	; Vista/7 32: http://mse.dlservice.microsoft.com/download/A/3/8/A38FFBF2-1122-48B4-AF60-E44F6DC28BD8/enus/x86/mseinstall.exe
	; Vista/7 64: http://mse.dlservice.microsoft.com/download/A/3/8/A38FFBF2-1122-48B4-AF60-E44F6DC28BD8/enus/amd64/mseinstall.exe 
	
	_record("Setting Up Microsoft Essentials")
	; Install Ms Essentials
	ShellExecuteWait("c:\techcleaner\apps\" & "mseinstall.exe","/s /runwgacheck")
	ShellExecuteWait("taskkill","/f /im msseces.exe") ; Kill 

	; Update Ms Essentials
	ShellExecuteWait("c:\techcleaner\apps\" & "mpam-fe.exe")
	
	sleep(2000) ; Sleep for 2 seconds to wait for ms essentials to update

	; Start Ms Essentials
	ShellExecute("C:\Program Files\Microsoft Security Client\MsMpEng.Exe")

	_record("Finished Setting Up Microsoft Essentials")
EndFunc

;;;;;;;;;;;;;;;;;;;;;
; Setup Our Steps
;;;;;;;;;;;;;;;;;;;;;

; Prepare System for cleaner apps / do initial sweep
Func _stepone()
	
	_record("<step>1</step>")
	
	; Kill Non-Whitelisted Processes
	_record("# Checking Processes")
	_prockill()

	; Check Version Against Github
	_record("# Checking for Updates")
	$current_version = _INetGetSource($updateurl&"VERSION",True)
	If $current_version <> $version Then
		;_record("New Updates Found")
	Else
		_record("No New Updates Found")
	EndIf

	; Check Services
	_record("# Checking Services")
	_srvchk()

	; Backup Registry
	_record("# Backing Up Registry")
	_regbckup()

	; Check Registry
	_record("# Checking Registry")
	_regchk()

	; Kill Any Proxies 
	_record("# Killing Any Proxies")
	_killproxy() ;~ Need to bug test this function & add to it ~

	; Search for Blocked Programs & Uninstall
	;_progchk()

	; Detect Hidden Desktop items etc...
	;_unhidechk()

	; Reset IE
	;_iereset()
	
	; Update finish of step 1
	IniWrite("C:\techcleaner\info.ini", "run", "last", "1")

	; We don't hook into step 2 because soemtimes we don't need to run step two
EndFunc

; Download and prepare cleaner apps for run
Func _steptwo()
	
	_record("<step>2</step>")
	
	; Download Our Tools
	_record("# Starting Downloads")
	InetGet("http://download.bleepingcomputer.com/dl/e012601d8fd5b2a50dfe61141c25d861/502c9c68/windows/security/anti-virus/c/combofix/ComboFix.exe","c:\techcleaner\apps\" & "aaaComboFixaaa.com")
	InetGet("http://download.bleepingcomputer.com/dl/e012601d8fd5b2a50dfe61141c25d861/502c9c68/windows/security/anti-virus/c/combofix/ComboFix.exe","c:\techcleaner\apps\" & "explorer.exe")
	InetGet("http://download.bleepingcomputer.com/dl/cc543da20dc48792d8950f78f0dae976/503ab215/windows/security/security-utilities/r/rkill/rkill.exe","c:\techcleaner\apps\" & "rkill.exe")
	InetGet("http://support.kaspersky.com/downloads/utils/tdsskiller.exe","c:\techcleaner\apps\" & "tdsskiller.exe")
	InetGet("http://www.piriform.com/ccleaner/download/portable/downloadfile","c:\techcleaner\apps\" & "ccsetup.zip")
	InetGet("http://www.eusing.com/Freedownload/EFRCSetup.exe","c:\techcleaner\apps\" & "registry cleaner - EFRCSetup.exe")
	InetGet("http://www.piriform.com/defraggler/download/portable/downloadfile","c:\techcleaner\apps\" & "dfsetup.zip")
	InetGet("http://usfiles.brothersoft.com/utilities/system_utilities/unlocker1.9.0-portable.zip","c:\techcleaner\apps\" & "unlocker-portable.zip")
	InetGet("http://www.revouninstaller.com/download/revouninstaller.zip","c:\techcleaner\apps\" & "revouninstaller.zip")

	$osv = @OSVersion
	$ost = @OSArch

	_record("OS Version: " $osv  & ,1)
	_record("Architecture Type: " $ost & ,1)
	If $osv = "WIN_XP" Or $osv = "WIN_XPe" Then
		; XP
		InetGet("http://mse.dlservice.microsoft.com/download/A/3/8/A38FFBF2-1122-48B4-AF60-E44F6DC28BD8/enus/x86/mseinstall.exe","c:\techcleaner\apps\" & "mseinstall.exe")
		_record("Getting MS Essentials XP",1)
	ElseIf $ost = "X64" Then
		; Vista/7 64
		InetGet("http://mse.dlservice.microsoft.com/download/A/3/8/A38FFBF2-1122-48B4-AF60-E44F6DC28BD8/enus/amd64/mseinstall.exe ","c:\techcleaner\apps\" & "mseinstall.exe")
		_record("Getting MS Essentials X64",1)
	Else
		; Vista/7 32
		InetGet("http://mse.dlservice.microsoft.com/download/A/3/8/A38FFBF2-1122-48B4-AF60-E44F6DC28BD8/enus/x86/mseinstall.exe","c:\techcleaner\apps\" & "mseinstall.exe")
		_record("Getting MS Essentials X32",1)
	EndIf
	
	; Download Ms Essential Updates
	If $ost = "X64" Then
		InetGet("http://go.microsoft.com/fwlink/?LinkID=87342","c:\techcleaner\apps\" & "mpam-fe.exe")
	Else
		InetGet("http://go.microsoft.com/fwlink/?LinkID=87341","c:\techcleaner\apps\" & "mpam-fe.exe")
	EndIf

	_record("# Finished Downloads")

	; Prepare Files
	_record("# Preparing Downloads for Operation")
	_Zip_UnzipAll("c:\techcleaner\apps\" & "ccsetup.zip", "c:\techcleaner\apps\" & "ccleaner\", 0) 
	_Zip_UnzipAll("c:\techcleaner\apps\" & "dfsetup.zip", "c:\techcleaner\apps\" & "defraggler\", 0) 
	_Zip_UnzipAll("c:\techcleaner\apps\" & "unlocker-portable.zip", "c:\techcleaner\apps\" & "unlocker\", 0) 
	_Zip_UnzipAll("c:\techcleaner\apps\" & "revouninstaller.zip", "c:\techcleaner\apps\" & "revouninstaller\", 0) 
	FileDelete("c:\techcleaner\apps\" & "ccsetup.zip")
	FileDelete("c:\techcleaner\apps\" & "dfsetup.zip")
	FileDelete("c:\techcleaner\apps\" & "unlocker-portable.zip")
	FileDelete("c:\techcleaner\apps\" & "revouninstaller.zip")
	_record("# Finished Preparing Downloads for Operation")
	
	; Update finish of step
	IniWrite("C:\techcleaner\info.ini", "run", "last", "2")

	_stepthree()

EndFunc

Func _stepthree()

	_record("<step>3</step>")

	_stepthreepointone()

	_stepthreepointtwo()

	_stepthreepointthree()

	_stepthreepointfour()

	IniWrite("C:\techcleaner\info.ini", "run", "last", "1")

	_stepfour()

EndFunc

;We dive step 3 (major scanners into sub steps)

; RKill
Func _stepthreepointone()
	_record("<step>3.1</step>")
	_record("Running RKill")
	runwait("c:\techcleaner\apps\rkill.exe")  ; need to build in a detection for it being killed
EndFunc

; TDSKiller
Func _stepthreepointtwo()
	_record("<step>3.2</step>")
	_record("Running TDSKiller")
	runwait("c:\techcleaner\apps\TDSSKiller.exe -silent  -dcexact -l c:\techcleaner\logs\tdskiller-report-" & $time & ".txt")
EndFunc

; ComboFix
Func _stepthreepointthree()
	_record("<step>3.3</step>")
	_record("Running Combofix")
	runwait("c:\techcleaner\apps\aaaComboFixaaa.com") ; need to build in a detection for it being killed
EndFunc

Func _stepfour()

	_record("<step>4</step>")

	; Add MS Essentials to Help Keep Things Up to Date & Working
	_msessentials()

	; Clean TMP Folders & Junk Out
	_ccleaner()  ; idk if working

	; Degrag our harddrive
	_defraggler() ; idk if working

	IniWrite("C:\techcleaner\info.ini", "run", "last", "4")
EndFunc


;;;;;;;;;;;;;;;;;;;;;
; The Lopp
;;;;;;;;;;;;;;;;;;;;;

Func _loop()
	; Do our initial function
	_initial()

	; Start Progress Bar
	ProgressOn("Tech Cleaner - Copyright: Anthony Kosednar | V: " & $version, "Cleaner Progress", "Starting Up...")

	; Check for a run in process
	Global $finished = IniRead("C:\techcleaner\info.ini", "run", "finished", "no")
	Global $laststep = IniRead("C:\techcleaner\info.ini", "run", "last","0")

	; Check for first run ever
	If Not FileExists("C:\techcleaner\info.ini") Then
		$finished = "yes"
	EndIf

	If $finished == "yes" Then
		Global $time = _TimeGetStamp()
		Global $logz = "c:\techcleaner\logs\alert-" & $time & ".log"
		; House Keeping
		_housekeeping()
		; Reset Last Step
		Global $laststep = 0
	Else
		ProgressSet(100*(0.1*$laststep), "Preforming Step " & $laststep)
		Global $time = IniRead("C:\techcleaner\info.ini", "run", "time", _TimeGetStamp())
		Global $logz = "c:\techcleaner\logs\alert-" & $time & ".log"		
	EndIf

	; Set Some Variables based on initialization
	Global $alert = FileOpen($logz, 1)
	Global $alerthistory = FileOpen("c:\techcleaner\logs\alert-history.log", 1)
	Global $complete = FileOpen("c:\techcleaner\logs\complete.log", 1)
	Global $general = FileOpen("c:\techcleaner\logs\general.log", 1)

	; Record Our Start
	_record("Cleaner Started  (Version: "& $version & ") | Time: " & $time,1)
	IniWrite("C:\techcleaner\info.ini", "run", "time", $time)
	_record("Last Step: " & $laststep)

	;;;;;;;;;;;;;;;;;;;;;
	; Our Step Logic
	;;;;;;;;;;;;;;;;;;;;;


	; Always run step 1
	;_stepone()

	; Note: we recall the last step that was in the ini file before anything ran
	;Switch $laststep
	;    Case 1 ; if we have finished 1 then we need to run 2
	;	_steptwo()
	;   Case 2  ; if we have finished 2 then we need to run 3
	;      	_stepthree()
	;   Case 3  ; if we have finished 2 then we need to run 4
	;	_stepfour()
	;    Case 4  ; Opps some how it got through 4 but did not report as finished so lets restart
		_initial()
		_housekeeping()
		_stepone()
		_steptwo()
	;   Case Else ; if we have 0 then we know we have already ran step 1 so it needs to be step 2
	;	_steptwo()
	;EndSwitch


	FileClose($alert)
	FileClose($alerthistory)
	FileClose($complete)
	FileClose($general)

	;;;;;;;;;;;;;;;;;;;;;
	; Finish Run
	;;;;;;;;;;;;;;;;;;;;;

	IniWrite("C:\techcleaner\info.ini", "run", "finished", "yes")

	Sleep(750)
	ProgressOff()

	If $criticalalert > 0 Then
	   	MsgBox(0, "Tech Cleaner - Copyright: Anthony Kosednar | V: " & $version, "System Cleaned!" & @CRLF & @CRLF & $criticalalert & " Immediate Problems Found." & @CRLF  & @CRLF & "Please check logs of other scans for more details.")
		ShellExecute("notepad.exe", $logz)
	Else
		MsgBox(0,"Tech Cleaner - Copyright: Anthony Kosednar | V: " & $version, "System Cleaned!" & @CRLF & @CRLF & "No Immediate Problems Found." & @CRLF  & @CRLF & "Please check logs of other scans for more details.")
	EndIf
EndFunc


;;;;;;;;;;;;;;;;;;;;;
; Start Main Thread
;;;;;;;;;;;;;;;;;;;;;
_loop()