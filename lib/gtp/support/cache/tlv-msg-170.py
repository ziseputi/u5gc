ies = []
ies.append({"ie_type": "EBI", "ie_value": "List of RABs", "presence": "C", "instance": "0",
            "comment": "Shall be present on S4 interface when this message is used to release a subset of all active RABs according to the RAB release procedure.Several IEs with this type and instance values shall be included as necessary to represent a list of RABs to be released."})
ies.append({"ie_type": "Node Type", "ie_value": "Originating Node", "presence": "CO", "instance": "0",
            "comment": "This IE shall be sent on S11 interface, if ISR is active in the MME.This IE shall be sent on S4 interface, if ISR is active in the SGSNSee NOTE 1."})
ies.append({"ie_type": "Indication", "ie_value": "Indication Flags", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included if any one of the applicable flags is set to 1.Applicable flags are:Abnormal Release of Radio Link: This flag shall be set to 1 on the S11 interface -	if the S1 release is due to an abnormal release of the radio link, e.g. when the MME receives UE CONTEXT RELEASE REQUEST with the cause value set to Radio Connection With UE Lost, or-	if the MME performs DL data buffering and the operator specified policy/configuration conditions for triggering the PGW pause of charging are met (e.g. number/fraction of packets/bytes dropped at MME in downlink) as specified in subclause 5.3.6A of 3GPP TS23.401 [3]."})
msg_list[key]["ies"] = ies
