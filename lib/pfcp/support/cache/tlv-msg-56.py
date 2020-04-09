ies = []
ies.append({"ie_type": "Report Type", "ie_value": "Report Type", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall indicate the type of the report."})
ies.append({"ie_type": "Downlink Data Report", "ie_value": "Downlink Data Report", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Report Type indicates a Downlink Data Report. "})
ies.append(
    {"ie_type": "Usage Report Session Report Request", "ie_value": "Usage Report", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the Report Type indicates a Usage Report.Several IEs within the same IE type may be present to represent a list of Usage Reports."})
ies.append(
    {"ie_type": "Error Indication Report", "ie_value": "Error Indication Report", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the Report Type indicates an Error Indication Report. "})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "Load Control Information", "presence": "O", "tlv_more": "0",
     "comment": "The UP function may include this IE if it supports the load control feature and the feature is activated in the network.See Table 7.5.3.3-1."})
ies.append({"ie_type": "Overload Control Information", "ie_value": "Overload Control Information", "presence": "O",
            "tlv_more": "0",
            "comment": "During an overload condition, the UP function may include this IE if it supports the overload control feature and the feature is activated in the network.See Table 7.5.3.4-1."})
ies.append({"ie_type": "Additional Usage Reports Information", "ie_value": "Additional Usage Reports Information",
            "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included in one additional PFCP Session Report Request message, if the PFCP Session Modification Response indicated that more reports would follow (i.e. if the AURI flag was set to 1) (see clause 5.2.2.3.1).When present, this IE shall indicate the total number of usage reports that need to be sent in PFCP Session Report Request messages.   "})
ies.append({"ie_type": "PFCPSRReq-Flags", "ie_value": "PFCPSRReq-Flags", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if at least one of the flags is set to 1.-	PSDBU (PFCP Session Deleted By the UP function): if both the CP function and UP function support the EPFAR feature, the UP function may set this flag if the UP function needs to delete the PFCP session, e.g. to report all remaining non-zero usage reports for all URRs in the PFCP Session and the PFCP session is being deleted locally in the UP function."})
ies.append({"ie_type": "F-SEID", "ie_value": "Old CP F-SEID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UPF sends the PFCP Session Report Request to a different SMF in an SMF Set. See clauses 5.22.2 and 5.22.3.When present, it shall indicate the CP F-SEID assigned by the previous SMF to the PFCP session. "})
msg_list[key]["ies"] = ies
