ies = []
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Contexts", "presence": "M", "instance": "0",
            "comment": "This IE shall be used to indicate dedicated bearers. When used, at least one dedicated bearer shall be present. Several IEs with this type and instance values shall be included as necessary to represent a list of Bearers"})
ies.append({"ie_type": "ULI", "ie_value": "User Location Information", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included by the MME on the S11 interface or by the SGSN on the S4 interface. The CGI/SAI shall be included by SGSN and the ECGI shall be included by MME.The SGW shall forward this IE on the S5/S8 interface if it receives it from the MME/SGSN. See NOTE 1."})
ies.append({"ie_type": "ULI Timestamp", "ie_value": "ULI Timestamp", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included on the S4/S11 interface if the ULI IE is present. It indicates the time when the User Location Information was acquired. The SGW shall include this IE on S5/S8 if the SGW receives it from the MME/SGSN. "})
ies.append({"ie_type": "UE Time Zone", "ie_value": "UE Time Zone", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included, if available, by the MME on the S11 interface or by the SGSN on the S4 interface. "})
ies.append({"ie_type": "Overload Control Information", "ie_value": "MME/S4-SGSN's Overload Control Information",
            "presence": "O", "instance": "0",
            "comment": "During an overload condition, the MME/S4-SGSN may include this IE on the S11/S4 interface if the overload control feature is supported by the MME/S4-SGSN and is activated for the PLMN to which the PGW belongs (see clause 12.3.11).When present, the MME/S4-SGSN shall provide only one instance of this IE, representing its overload information."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "SGW's Overload Control Information", "presence": "O",
     "instance": "1",
     "comment": "During an overload condition, the SGW may include this IE over the S5/S8 interface if the overload control feature is supported by the SGW and is activated for the PLMN to which the PGW belongs (see clause 12.3.11).When present, the SGW shall provide only one instance of this IE, representing its overload information."})
ies.append({"ie_type": "F-TEID", "ie_value": "Sender F-TEID for Control Plane", "presence": "CO", "instance": "0",
            "comment": "The SGW shall include this IE on the S5/S8 interfaces and set it to the last value sent to the PGW.If the Sender F-TEID for Control Plane is received, the PGW shall only handle the Delete Bearer Command message if the Sender F-TEID for Control Plane in this message is the same as the last Sender F-TEID for Control Plane received on the given interface."})
msg_list[key]["ies"] = ies
