ies = []
ies.append({"ie_type": "Cause", "ie_value": "Cause", "presence": "M", "instance": "0", "comment": ""})
ies.append({"ie_type": "Recovery", "ie_value": "Recovery", "presence": "C", "instance": "0",
            "comment": "This IE shall be included on the S5/S8, S4/S11 and S2a/S2b interfaces if contacting the peer for the first time "})
ies.append({"ie_type": "PCO", "ie_value": "Protocol Configuration Options", "presence": "C", "instance": "0",
            "comment": "The PGW shall include Protocol Configuration Options (PCO) IE on the S5/S8 interface, if available and if the UE or the network does not support ePCO.If SGW receives this IE, SGW shall forward it to SGSN/MME on the S4/S11 interface."})
ies.append({"ie_type": "Indication", "ie_value": "Indication Flags", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included if any one of the applicable flags is set to 1.Applicable flags are:Associate OCI with PGW nodes identity: The PGW shall set this flag to 1 on the S5/S8 interface or S2a/S2b interface if it has included the PGWs Overload Control Information and if this information is to be associated with the node identity (i.e. FQDN or the IP address received from the HSS or DNS during the PGW selection) of the serving PGW. The SGW shall set this flag on the S11/S4 interface if it supports the overload control feature and if the flag is set on the S5/S8 interface.Associate OCI with SGW nodes identity: The SGW shall set this flag to 1 on the S11/S4 interface if it has included the SGWs Overload Control Information and if this information is to be associated with the node identity (i.e. FQDN or the IP address received from the DNS during the SGW selection) of the serving SGW."})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "PGW's node level Load Control Information", "presence": "O",
     "instance": "0",
     "comment": "The PGW may include this IE on the S5/S8 or S2a/S2b interface, providing its node level load information, if the load control feature is supported by the PGW and is activated for the PLMN to which the access network node, i.e. MME/S4-SGSN for 3GPP access network, ePDG/TWAN for non-3GPP access network, belongs (see clause 12.2.6)."})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "PGW's APN level Load Control Information", "presence": "O",
     "instance": "1",
     "comment": "The PGW may include this IE on the S5/S8 or S2a/S2b interface, providing APN level load information, if the APN level load control feature is supported by the PGW and is activated for the PLMN to which the access network node, i.e. MME/S4-SGSN for 3GPP access network, ePDG/TWAN for non-3GPP access based network, belongs (see clause 12.2.6).When present, the PGW shall provide one or more instances of this IE, up to maximum of 10, with the same type and instance value, each representing the load information for a list of APN(s).See NOTE 1, NOTE 3."})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "SGW's node level Load Control Information", "presence": "O",
     "instance": "2",
     "comment": "The SGW may include this IE, over the S11/S4 interface if the load control feature is supported by the SGW and is activated in the network (see clause 12.2.6).When present, the SGW shall provide only one instance of this IE, representing its node level load information."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "PGW's Overload Control Information", "presence": "O",
     "instance": "0",
     "comment": "During an overload condition, the PGW may include this IE on the S5/S8 or S2a/S2b interface, if the overload control feature is supported by the PGW and is activated for the PLMN to which the access network node, i.e. MME/S4-SGSN for 3GPP access based network, ePDG/TWAN for non-3GPP access based network, belongs (see clause 12.3.11).When present, the PGW shall provide at least one instance of this IE, representing its overload information. Additionally, the PGW may indicate APN level overload control by providing, one or more instances of this IE, up to maximum of 10, with the same type and instance value, each representing the overload information for a list of APN(s).See NOTE 2, NOTE 4."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "SGW's Overload Control Information", "presence": "O",
     "instance": "1",
     "comment": "During an overload condition, the SGW may include this IE over the S11/S4 interface if the overload control feature is supported by the SGW and is activated in the network (see clause 12.3.11).When present, the SGW shall provide only one instance of this IE, representing its overload information."})
ies.append({"ie_type": "ePCO", "ie_value": "Extended Protocol Configuration Options", "presence": "CO", "instance": "0",
            "comment": "The PGW shall include Extended Protocol Configuration Options (ePCO) IE on the S5/S8 interface, if available and if the UE and the network support ePCO.If the SGW receives this IE, the SGW shall forward it to the MME on the S11 interface."})
msg_list[key]["ies"] = ies
