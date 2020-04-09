ies = []
ies.append({"ie_type": "Node ID", "ie_value": "Node ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall contain the unique identifier of the sending Node."})
ies.append({"ie_type": "UP Function Features", "ie_value": "UP Function Features", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall indicate the supported Features when the sending node is the UP function."})
ies.append({"ie_type": "CP Function Features", "ie_value": "CP Function Features", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall indicate the supported Features when the sending node is the CP function."})
ies.append(
    {"ie_type": "PFCP Association Release Request", "ie_value": "PFCP Association Release Request", "presence": "C",
     "tlv_more": "0",
     "comment": "This IE shall be present if the UP function requests the CP function to release the PFCP association."})
ies.append(
    {"ie_type": "Graceful Release Period", "ie_value": "Graceful Release Period", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the UP function requests a graceful release of the PFCP association."})
ies.append(
    {"ie_type": "User Plane IP Resource Information", "ie_value": "User Plane IP Resource Information", "presence": "O",
     "tlv_more": "3",
     "comment": "This IE may be present if the UP function sends this message.When present, this IE shall contain an IPv4 and/or an IPv6 address, together with a TEID range that the CP function shall use to allocate GTP-U F-TEID in the UP function.Several IEs with the same IE type may be present to represent multiple User Plane IP Resources. "})
ies.append({"ie_type": "PFCPAUReq-Flags", "ie_value": "PFCPAUReq-Flags", "presence": "O", "tlv_more": "0",
            "comment": "This IE shall be included if at least one of the flags is set to 1.-	PARPS (PFCP Association Release Preparation Start): if both the CP function and UP function support the EPFAR feature, the CP or UP function may set this flag to 1 to indicate that the PFCP association is to be released and all non-zero usage reports for those PFCP Sessions affected by the release of the PFCP association shall be reported."})
ies.append({"ie_type": "Alternative SMF IP Address", "ie_value": "Alternative SMF IP Address", "presence": "O",
            "tlv_more": "0",
            "comment": "This IE may be present if the SMF advertises the support of the SSET feature in the CP Function Features IE (see clause 8.2.58).When present, this IE shall contain an IPv4 and/or IPv6 address of an alternative SMF.Several IEs with the same IE type may be present to represent multiple alternative SMF IP addresses. "})
msg_list[key]["ies"] = ies
