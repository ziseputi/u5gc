ies = []
ies.append({"ie_type": "Node ID", "ie_value": "Node ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall contain the unique identifier of the sending Node."})
ies.append({"ie_type": "Recovery Time Stamp", "ie_value": "Recovery Time Stamp", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall contain the time stamp when the CP or UP function was started, see clause 19A of 3GPPTS23.007[24]. (NOTE)"})
ies.append({"ie_type": "UP Function Features", "ie_value": "UP Function Features", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function sends this message and the UP function supports at least one UP feature defined in this IE.When present, this IE shall indicate the features the UP function supports."})
ies.append({"ie_type": "CP Function Features", "ie_value": "CP Function Features", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the CP function sends this message and the CP function supports at least one CP feature defined in this IE.When present, this IE shall indicate the features the CP function supports."})
type_list["User Plane IP Resource Information"]["max_tlv_more"] = "3"
ies.append(
    {"ie_type": "User Plane IP Resource Information", "ie_value": "User Plane IP Resource Information", "presence": "O",
     "tlv_more": "3",
     "comment": "This IE may be present if the UP function sends this message.When present, this IE shall contain an IPv4 and/or an IPv6 address, together with a TEID range that the CP function shall use to allocate GTP-U F-TEID in the UP function.Several IEs with the same IE type may be present to represent multiple User Plane IP Resources."})
ies.append({"ie_type": "UE IP Address", "ie_value": "UE IP address Pool Identity", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if the UP function sends this message.When present, this IE shall contain an UE IP address Pool IdentitySeveral IEs with the same IE type may be present to represent multiple UE IP address Pool Identities."})
ies.append({"ie_type": "Alternative SMF IP Address", "ie_value": "Alternative SMF IP Address", "presence": "O",
            "tlv_more": "0",
            "comment": "This IE may be present if the SMF advertises the support of the SSET feature in the CP Function Features IE (see clause 8.2.58).When present, this IE shall contain an IPv4 and/or IPv6 address of an alternative SMF.Several IEs with the same IE type may be present to represent multiple alternative SMF IP addresses. "})
ies.append({"ie_type": "SMF Set ID", "ie_value": "SMF Set ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the SMF advertises the support of the MPAS feature in the CP Function Features IE (see clause 5.22.3).When present, this IE shall contain an FQDN representing the SMF set to which the SMF belongs. "})
msg_list[key]["ies"] = ies
