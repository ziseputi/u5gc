ies = []
ies.append({"ie_type": "F-SEID", "ie_value": "CP F-SEID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the CP function decides to change its F-SEID for the PFCP session. The UP function shall use the new CP F-SEID for subsequent PFCP Session related messages for this PFCP Session. See Note 2."})
type_list["Remove PDR"]["max_tlv_more"] = "3"
ies.append({"ie_type": "Remove PDR", "ie_value": "Remove PDR", "presence": "C", "tlv_more": "3",
            "comment": "When present, this IE shall contain the PDR Rule which is requested to be removed. See Table 7.5.4-6-1.Several IEs within the same IE type may be present to represent a list of PDRs to remove."})
type_list["Remove FAR"]["max_tlv_more"] = "3"
ies.append({"ie_type": "Remove FAR", "ie_value": "Remove FAR", "presence": "C", "tlv_more": "3",
            "comment": "When present, this IE shall contain the FAR Rule which is requested to be removed. See Table 7.5.4-7-1.Several IEs within the same IE type may be present to represent a list of FARs to remove."})
type_list["Remove URR"]["max_tlv_more"] = "1"
ies.append({"ie_type": "Remove URR", "ie_value": "Remove URR", "presence": "C", "tlv_more": "1",
            "comment": "When present, this shall contain the URR Rule which is requested to be removed. See Table 7.5.4-8-1.Several IEs within the same IE type may be present to represent a list of URRs to remove."})
type_list["Remove QER"]["max_tlv_more"] = "1"
ies.append({"ie_type": "Remove QER", "ie_value": "Remove QER", "presence": "C", "tlv_more": "1",
            "comment": "When present, this IE shall contain the QER Rule which is requested to be removed. See Table 7.5.4-9-1.Several IEs within the same IE type may be present to represent a list of QERs to remove."})
ies.append({"ie_type": "Remove BAR", "ie_value": "Remove BAR", "presence": "C", "tlv_more": "0",
            "comment": "When present, this IE shall contain the BAR Rule which is requested to be removed. See Table 7.5.4.12-1."})
ies.append(
    {"ie_type": "Remove Traffic Endpoint", "ie_value": "Remove Traffic Endpoint", "presence": "C", "tlv_more": "0",
     "comment": "When present, this IE shall contain the Traffic Endpoint ID identifying the traffic endpoint to be removed, if the UP function has indicated support of PDI optimization.All the PDRs that refer to the removed Traffic Endpoint shall be deleted.See Table 7.5.4.14-1."})
type_list["Create PDR"]["max_tlv_more"] = "3"
ies.append({"ie_type": "Create PDR", "ie_value": "Create PDR", "presence": "C", "tlv_more": "3",
            "comment": "This IE shall be present if the CP function requests the UP function to create a new PDR.See Table 7.5.2.2-1.Several IEs within the same IE type may be present to represent a list of PDRs to create."})
type_list["Create FAR"]["max_tlv_more"] = "3"
ies.append({"ie_type": "Create FAR", "ie_value": "Create FAR", "presence": "C", "tlv_more": "3",
            "comment": "This IE shall be present if the CP function requests the UP function to create a new FAR.See Table 7.5.2.3-1.Several IEs within the same IE type may be present to represent a list of FARs to create."})
type_list["Create URR"]["max_tlv_more"] = "1"
ies.append({"ie_type": "Create URR", "ie_value": "Create URR", "presence": "C", "tlv_more": "1",
            "comment": "This IE shall be present if the CP function requests the UP function to create a new URR. See Table 7.5.2.4-1.Several IEs within the same IE type may be present to represent a list of URRs to create."})
type_list["Create QER"]["max_tlv_more"] = "1"
ies.append({"ie_type": "Create QER", "ie_value": "Create QER", "presence": "C", "tlv_more": "1",
            "comment": "This IE shall be present if the CP function requests the UP function to create a new QER. See Table 7.5.2.5-1.Several IEs within the same IE type may be present to represent a list of QERs to create."})
ies.append({"ie_type": "Create BAR", "ie_value": "Create BAR", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the CP function requests the UP function to create a new BAR.See Table 7.5.2.6-1."})
ies.append(
    {"ie_type": "Create Traffic Endpoint", "ie_value": "Create Traffic Endpoint", "presence": "C", "tlv_more": "0",
     "comment": "When present this IE shall contain the information associated with the Traffic Endpoint to be created, if the UP function has indicated support of PDI optimization. See Table 7.5.2.7-1."})
type_list["Update PDR"]["max_tlv_more"] = "3"
ies.append({"ie_type": "Update PDR", "ie_value": "Update PDR", "presence": "C", "tlv_more": "3",
            "comment": "This IE shall be present if a PDR previously created for the PFCP session need to be modified. See Table 7.5.4.2-1.Several IEs within the same IE type may be present to represent a list of PDRs to update."})
type_list["Update FAR"]["max_tlv_more"] = "3"
ies.append({"ie_type": "Update FAR", "ie_value": "Update FAR", "presence": "C", "tlv_more": "3",
            "comment": "This IE shall be present if a FAR previously created for the PFCP session need to be modified. See Table 7.5.4.3-1. Several IEs within the same IE type may be present to represent a list of FARs to update."})
type_list["Update URR"]["max_tlv_more"] = "1"
ies.append({"ie_type": "Update URR", "ie_value": "Update URR", "presence": "C", "tlv_more": "1",
            "comment": "This IE shall be present if URR(s) previously created for the PFCP session need to be modified.Several IEs within the same IE type may be present to represent a list of modified URRs. Previously URRs that are not modified shall not be included. See Table 7.5.4.4-1."})
type_list["Update QER"]["max_tlv_more"] = "1"
ies.append({"ie_type": "Update QER", "ie_value": "Update QER", "presence": "C", "tlv_more": "1",
            "comment": "This IE shall be present if QER(s) previously created for the PFCP session need to be modified.Several IEs within the same IE type may be present to represent a list of modified QERs.Previously created QERs that are not modified shall not be included.See Table 7.5.4.5-1."})
ies.append(
    {"ie_type": "Update BAR Session Modification Request", "ie_value": "Update BAR", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if a BAR previously created for the PFCP session needs to be modified.A previously created BAR that is not modified shall not be included.See Table 7.5.4.11-1."})
ies.append(
    {"ie_type": "Update Traffic Endpoint", "ie_value": "Update Traffic Endpoint", "presence": "C", "tlv_more": "0",
     "comment": "When present this IE shall contain the information associated with the traffic endpoint to be updated, if the UP function has indicated support of PDI optimization.All the PDRs that refer to the Traffic Endpoint shall use the updated Traffic Endpoint information.See Table 7.5.4.13-1."})
ies.append({"ie_type": "PFCPSMReq-Flags", "ie_value": "PFCPSMReq-Flags", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if at least one of the flags is set to 1.-	DROBU (Drop Buffered Packets): the CP function shall set this flag if the UP function is requested to drop the packets currently buffered for this PFCP session (see NOTE 1).-	QAURR (Query All URRs): the CP function shall set this flag if the CP function requests immediate usage report(s) for all the URRs previously provisioned for this PFCP session (see NOTE 3). "})
ies.append({"ie_type": "Query URR", "ie_value": "Query URR", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the CP function requests immediate usage report(s) to the UP function.Several IEs within the same IE type may be present to represent a list of URRs for which an immediate report is requested.See Table 7.5.4.10-1.See NOTE 3."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "PGW-C FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause 23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "SGW-C FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause 23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "MME FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause 23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "ePDG FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause 23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "TWAN FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause 23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "User Plane Inactivity Timer", "ie_value": "User Plane Inactivity Timer", "presence": "C",
            "tlv_more": "0", "comment": "This IE shall be present if it needs to be changed."})
ies.append({"ie_type": "Query URR Reference", "ie_value": "Query URR Reference", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if the Query URR IE is present or the QAURR flag is set to 1. When present, it shall contain a reference identifying the query request, which the UP function shall return in any usage report sent in response to the query."})
ies.append({"ie_type": "Trace Information", "ie_value": "Trace Information", "presence": "O", "tlv_more": "0",
            "comment": "When present, this IE shall contain the trace instructions to be applied by the UP function for this PFCP session.A Trace Information with a null length indicates that the trace session shall be deactivated. "})
ies.append({"ie_type": "Remove MAR", "ie_value": "Remove MAR", "presence": "C", "tlv_more": "0",
            "comment": "When present, this IE shall contain the MAR Rule which is requested to be removed. See Table 7.5.4.15-1.Several IEs within the same IE type may be present to represent a list of MARs to remove."})
ies.append({"ie_type": "Update MAR", "ie_value": "Update MAR", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a MAR previously created for the PFCP session needs to be modified. See Table 7.5.4.16-1.Several IEs within the same IE type may be present to represent a list of MARs to update."})
ies.append({"ie_type": "Create MAR", "ie_value": "Create MAR", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the CP function requests the UP function to create a new MAR for a new PDR. See Table 7.5.2.8-1.Several IEs within the same IE type may be present to represent a list of MARs to create."})
ies.append({"ie_type": "Node ID", "ie_value": "Node ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a new SMF in an SMF Set, with one PFCP association per SMF and UPF (see clause 5.22.3), takes over the control of the PFCP session.When present, it shall contain the unique identifier of the new SMF."})
msg_list[key]["ies"] = ies
