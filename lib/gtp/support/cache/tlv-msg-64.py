ies = []
ies.append({"ie_type": "AMBR", "ie_value": "APN-Aggregate Maximum Bit Rate", "presence": "M", "instance": "0",
            "comment": "This IE shall contain the APN-AMBR value received by the MME/SGSN/ TWAN/ePDG from the HSS."})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Context", "presence": "M", "instance": "0",
            "comment": "Only one IE with this type and instance value shall be included and this shall represent the Default Bearer."})
ies.append({"ie_type": "Overload Control Information", "ie_value": "MME/S4-SGSN's Overload Control Information",
            "presence": "O", "instance": "0",
            "comment": "During an overload condition, the MME/S4-SGSN may include this IE on the S11/S4 interface if the overload control feature is supported by the MME/S4-SGSN and is activated for the PLMN to which the PGW belongs (see clause 12.3.11).When present, the MME/S4-SGSN shall provide only one instance of this IE, representing its overload information."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "SGW's Overload Control Information", "presence": "O",
     "instance": "1",
     "comment": "During an overload condition, the SGW may include this IE over the S5/S8 interface if the overload control feature is supported by the SGW and is activated for the PLMN to which the PGW belongs (see clause 12.3.11).When present, the SGW shall provide only one instance of this IE, representing its overload information."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "TWAN/ePDG's Overload Control Information", "presence": "O",
     "instance": "2",
     "comment": "During an overload condition, the TWAN/ePDG may include this IE over the S2a/S2b interface if the overload control feature is supported by the TWAN/ePDG and is activated for the PLMN to which the PGW belongs (see clause 12.3.11).When present, the TWAN/ePDG shall provide only one instance of this IE, representing its overload information."})
ies.append({"ie_type": "F-TEID", "ie_value": "Sender F-TEID for Control Plane", "presence": "CO", "instance": "0",
            "comment": "The SGW shall include this IE on the S5/S8 interfaces and set it to the last value sent to the PGW.If the Sender F-TEID for Control Plane is received, the PGW shall only handle the Modify Bearer Command message if the Sender F-TEID for Control Plane in this message is the same as the last Sender F-TEID for Control Plane received on the given interface."})
msg_list[key]["ies"] = ies
