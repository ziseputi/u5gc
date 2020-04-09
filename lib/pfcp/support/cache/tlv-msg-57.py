ies = []
ies.append({"ie_type": "Cause", "ie_value": "Cause", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall indicate the acceptance or the rejection of the corresponding request message."})
ies.append({"ie_type": "Offending IE", "ie_value": "Offending IE", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if the rejection is due to a conditional or mandatory IE missing or faulty."})
ies.append(
    {"ie_type": "Update BAR PFCP Session Report Response", "ie_value": "Update BAR", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if a BAR previously created for the PFCP session needs to be modified.A previously created BAR that is not modified shall not be included.See Table 7.5.9.2-1."})
ies.append({"ie_type": "PFCPSRRsp-Flags", "ie_value": "PFCPSRRsp-Flags", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if at least one of the flags is set to 1.-	DROBU (Drop Buffered Packets): the CP function shall set this flag if the UP function needs to drop the packets currently buffered for this PFCP session (see NOTE 1)."})
ies.append({"ie_type": "F-SEID", "ie_value": "CP F-SEID", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be set by the SMF if the UPF indicated support of PFCP sessions successively controlled by different SMFs of a same SMF Set and the Cause IE indicates Request accepted (success)(see clause 5.22).When present, it shall be set to the new F-SEID that the UPF shall use for sending subsequent PFCP session related messages."})
ies.append({"ie_type": "F-TEID", "ie_value": "N4-u F-TEID", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be set by the SMF if the UPF indicated support of PFCP sessions successively controlled by different SMFs of a same SMF Set and the Cause IE indicates Request accepted (success).When present, it shall be set to the new N4-u F-TEID that the UPF shall use for data forwarding towards the SMF. "})
ies.append({"ie_type": "Alternative SMF IP Address", "ie_value": "Alternative SMF IP Address", "presence": "O",
            "tlv_more": "0",
            "comment": "This IE may be set by the SMF if the UPF indicated support of PFCP sessions successively controlled by different SMFs of a same SMF Set and the Cause IE indicates Redirection Requested (see clause 5.22).When present, it shall be set to the IP address of the new SMF to contact. "})
msg_list[key]["ies"] = ies
