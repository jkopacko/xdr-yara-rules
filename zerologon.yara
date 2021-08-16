rule SophosXDR_ZeroLogon_Detection
{
	meta:
		vulnerability = "CVE-2020-1472"
		description = "Detection of Zerologon Exploit"
		reference = "<https://community.sophos.com/b/security-blog/posts/microsoft-cve-2020-1472-netlogon-elevation-of-privilege-vulnerability-aka-zerologon>"		
    reference = "<https://nakedsecurity.sophos.com/2020/09/17/zerologon-hacking-windows-servers-with-a-bunch-of-zeros/>"   
    
    strings:
        $cvePattern = { 00 24 00 00 00 06 00 (0? | 10) 00 00 00 00 00 00 00 (0? | 10) 00 00 00 [1-29] 00 00 00 00 00 00 00 00 00 00 00 (ff | ef) ff (2f | 2e) 21 }

    condition:
        $cvePattern
}
