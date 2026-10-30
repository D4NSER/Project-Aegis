rule Aegis_Control_Marker
{
    meta:
        purpose = "Inert marker control only; not malware classification"
    strings:
        $marker = "AEGIS_CONTROL_MARKER"
    condition:
        $marker
}
