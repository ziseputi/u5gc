ies = []
ies.append({"ie_type": "IMSI", "ie_value": "IMSI", "presence": "C", "instance": "0",
            "comment": "This IE shall be included by the MME/SGSN if the SGW that the MME/SGSN selects for indirect data forwarding is different from the SGW already in use for the UE as the anchor point except for the case: -	If the UE is emergency attached and the UE is UICClessWhen the IMSI is included in the message, it is not used as an identifier-	if UE is emergency attached but IMSI is not authenticated.See NOTE1."})
ies.append({"ie_type": "MEI", "ie_value": "ME Identity", "presence": "C", "instance": "0",
            "comment": "This IE shall be included by the MME/SGSN if the SGW that the MME/SGSN selects for indirect data forwarding is different from the SGW already in use for the UE as the anchor point and if one of the following condition satisfies:-	If the UE is emergency attached and the UE is UICCless-	If the UE is emergency attached and the IMSI is not authenticated"})
ies.append({"ie_type": "Indication", "ie_value": "Indication Flags", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included if any one of the applicable flags is set to 1.Applicable flags are:Unauthenticated IMSI: This flag shall be set to 1 if the IMSI present in the message is not authenticated and is for an emergency attached UE."})
ies.append({"ie_type": "F-TEID", "ie_value": "Sender F-TEID for Control Plane", "presence": "C", "instance": "0",
            "comment": "This IE shall be included by the MME/SGSN if the SGW that the MME/SGSN selects for indirect data forwarding is different from the SGW already in use for the UE as the anchor point.See NOTE1."})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 0", "presence": "M", "instance": "0",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 1", "presence": "O", "instance": "1",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 2", "presence": "O", "instance": "2",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 3", "presence": "O", "instance": "3",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 4", "presence": "O", "instance": "4",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 5", "presence": "O", "instance": "5",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 6", "presence": "O", "instance": "6",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 7", "presence": "O", "instance": "7",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 8", "presence": "O", "instance": "8",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 9", "presence": "O", "instance": "9",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context 10", "presence": "O", "instance": "10",
            "comment": "Several IEs with this type and instance value may be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "Recovery", "ie_value": "Recovery", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included if contacting the peer for the first time."})
msg_list[key]["ies"] = ies
