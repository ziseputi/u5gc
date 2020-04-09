ies = []
ies.append({"ie_type": "Node ID", "ie_value": "Node ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall contain the unique identifier of the sending Node."})
ies.append({"ie_type": "F-SEID", "ie_value": "CP F-SEID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall contain the unique identifier allocated by the CP function identifying the session."})
ies.append({"ie_type": "Create PDR", "ie_value": "Create PDR", "presence": "M", "tlv_more": "3",
            "comment": "This IE shall be present for at least one PDR to be associated to the PFCP session.Several IEs with the same IE type may be present to represent multiple PDRs.See Table 7.5.2.2-1."})
ies.append({"ie_type": "Create FAR", "ie_value": "Create FAR", "presence": "M", "tlv_more": "3",
            "comment": "This IE shall be present for at least one FAR to be associated to the PFCP session.Several IEs with the same IE type may be present to represent multiple FARs.See Table 7.5.2.3-1."})
ies.append({"ie_type": "Create URR", "ie_value": "Create URR", "presence": "C", "tlv_more": "1",
            "comment": "This IE shall be present if a measurement action shall be applied to packets matching one or more PDR(s) of this PFCP session.Several IEs within the same IE type may be present to represent multiple URRs.See Table 7.5.2.4-1."})
ies.append({"ie_type": "Create QER", "ie_value": "Create QER", "presence": "C", "tlv_more": "1",
            "comment": "This IE shall be present if a QoS enforcement or QoS marking action shall be applied to packets matching one or more PDR(s) of this PFCP session.Several IEs within the same IE type may be present to represent multiple QERs.See Table 7.5.2.5-1."})
ies.append({"ie_type": "Create BAR", "ie_value": "Create BAR", "presence": "O", "tlv_more": "0",
            "comment": "When present, this IE shall contain the buffering instructions to be applied by the UP function to any FAR of this PFCP session set with the Apply Action requesting the packets to be buffered and with a BAR ID IE referring to this BAR. See table 7.5.2.6-1."})
ies.append(
    {"ie_type": "Create Traffic Endpoint", "ie_value": "Create Traffic Endpoint", "presence": "C", "tlv_more": "0",
     "comment": "This IE may be present if the UP function has indicated support of PDI optimization.Several IEs within the same IE type may be present to represent multiple Traffic Endpoints.See Table 7.5.2.7-1."})
ies.append({"ie_type": "PDN Type", "ie_value": "PDN Type", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the PFCP session is setup for an individual PDN connection or PDU session (see clause 5.2.1).When present, this IE shall indicate whether this is an IP or non-IP PDN connection/PDU session or, for 5GC, an Ethernet PDU session. See NOTE 3."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "SGW-C FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause23 of 3GPPTS 23.007[24]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "MME FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included when received on the S11 interface or on S5/S8 interface according to the requirements in clause23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "PGW-C FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "ePDG FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause 23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "TWAN FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "User Plane Inactivity Timer", "ie_value": "User Plane Inactivity Timer", "presence": "O",
            "tlv_more": "0",
            "comment": "This IE may be present to request the UP function to send a User Plane Inactivity Report when no user plane packets are received for this PFCP session for a duration exceeding the User Plane Inactivity Timer.When present, it shall contain the duration of the inactivity period after which a User Plane Inactivity Report shall be generated."})
ies.append({"ie_type": "User ID", "ie_value": "User ID", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present, based on operator policy. It shall only be sent if the UP function is in a trusted environment.See NOTE."})
ies.append({"ie_type": "Trace Information", "ie_value": "Trace Information", "presence": "O", "tlv_more": "0",
            "comment": "When present, this IE shall contain the trace instructions to be applied by the UP function for this PFCP session."})
ies.append({"ie_type": "APN/DNN", "ie_value": "APN/DNN", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present, if related functionalities in the UP function require the APN/DNN information. See NOTE 2."})
ies.append({"ie_type": "Create MAR", "ie_value": "Create MAR", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present for a N4 session established for a MA PDU session.Several IEs with the same IE type may be present to represent multiple MARs.See Table 7.5.2.8-1."})
msg_list[key]["ies"] = ies
