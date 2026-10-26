rule JS_HIPAA_Lure_jQuery_Dropper {
    meta:
        description     = "Detects HIPAA-themed JS dropper with jQuery camouflage, registry infection marker, and WSH execution"
        author          = "Malware Analysis - Final Project"
        date            = "2026-06-03"
        sample_sha256   = "9560fcb2abf1f071c2565870381104f1076cd71f0dd0200ef25ff15cb57f81a4"
        zip_sha256      = "566d48c7acb52cbe910bccc646d70a026ee25924cdb5751d3526864df49c69bb"
        reference       = "https://bazaar.abuse.ch"
        tlp             = "WHITE"

    strings:
        $jquery_header  = "jQuery JavaScript Library v3.6.0" ascii
        $sizzle         = "Sizzle CSS Selector Engine" ascii
        $noconflict     = "jQuery.noConflict" ascii

        $lure1          = "hipaa" nocase ascii wide
        $lure2          = "business_associate_agreement" nocase ascii wide
        $lure3          = "template_word" nocase ascii wide

        $reg_key        = "tHDtWG" ascii
        $reg_method     = "RegWrite" ascii
        $reg_hkcu       = "HKEY_CURRENT_USER" ascii

        $cipher_key     = "igWBKTAC" ascii

        $busywait       = "teeth18" ascii

        $payload_fn     = "nine0" ascii

    condition:
        filesize > 80KB and filesize < 400KB
        and $jquery_header
        and $sizzle
        and (
            ($cipher_key and $busywait and $payload_fn)
            or
            ($reg_key and $reg_method and $reg_hkcu)
            or
            ($noconflict and 2 of ($lure*))
        )
}


rule JS_WindowsScriptHost_Lure_Generic {
    meta:
        description = "Detects generic JS lure files with jQuery camouflage targeting Windows Script Host"
        author      = "Malware Analysis - Final Project"
        date        = "2026-06-03"
        tlp         = "WHITE"

    strings:
        $lure1          = "agreement"     nocase ascii wide
        $lure2          = "invoice"       nocase ascii wide
        $lure3          = "hipaa"         nocase ascii wide
        $lure4          = "contract"      nocase ascii wide
        $lure5          = "template_word" nocase ascii wide
        $jquery         = "jQuery v"      ascii
        $numeric_suffix = /[a-z_]{5,}\s+\d{4,6}\.js/ nocase ascii

    condition:
        filesize < 500KB
        and $jquery
        and (2 of ($lure*) or $numeric_suffix)
}


rule JS_Registry_Infection_Marker_tHDtWG {
    meta:
        description = "Detects the specific registry infection marker written by this JS dropper family"
        author      = "Malware Analysis - Final Project"
        date        = "2026-06-03"
        tlp         = "WHITE"

    strings:
        $marker     = "tHDtWG" ascii wide
        $hkcu       = "HKEY_CURRENT_USER" ascii
        $regwrite   = "RegWrite" ascii

    condition:
        all of them
}

