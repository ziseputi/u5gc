ies = []
ies.append({"ie_type": "Cause", "ie_value": "Cause", "presence": "M", "instance": "0", "comment": ""})
ies.append({"ie_type": "MSISDN", "ie_value": "MSISDN", "presence": "C", "instance": "0",
            "comment": "This IE shall be included on S5/S8 interfaces by the PGW if it is stored in its UE context and if this message is triggered due to TAU/RAU/HO with SGW relocation."})
ies.append({"ie_type": "EBI", "ie_value": "Linked EPS Bearer ID", "presence": "C", "instance": "0",
            "comment": "This IE shall be sent on S5/S8 when the UE moves from a Gn/Gp SGSN to the S4 SGSN or MME to identify the default bearer the PGW selects for the PDN Connection.This IE shall also be sent by SGW on S11, S4 during Gn/Gp SGSN to S4-SGSN/MME HO procedures to identify the default bearer the PGW selects for the PDN Connection."})
ies.append({"ie_type": "APN Restriction", "ie_value": "APN Restriction", "presence": "C ", "instance": "0",
            "comment": "This IE denotes the restriction on the combination of types of APN for the APN associated with this EPS bearer Context. This IE shall be included over S5/S8 interfaces, and shall be forwarded over S11/S4 interfaces during Gn/Gp SGSN to MME/S4-SGSN handover procedures. This IE shall also be included on S5/S8 interfaces during the Gn/Gp SGSN to S4 SGSN/MME RAU/TAU procedures.The target MME or SGSN determines the Maximum APN Restriction using the APN Restriction. "})
ies.append({"ie_type": "PCO", "ie_value": "Protocol Configuration Options", "presence": "C", "instance": "0",
            "comment": "If SGW receives this IE from PGW on GTP or PMIP based S5/S8, the SGW shall forward PCO to MME/S4-SGSN during Inter RAT handover from the UTRAN or from the GERAN to the E-UTRAN. See NOTE 2."})
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Contexts modified", "presence": "C", "instance": "0",
            "comment": "EPS bearers corresponding to Bearer Contexts to be modified that were sent in Modify Bearer Request message. Several IEs with the same type and instance value may be included as necessary to represent a list of the Bearers which are modified."})
ies.append(
    {"ie_type": "Bearer Context", "ie_value": "Bearer Contexts marked for removal", "presence": "C", "instance": "1",
     "comment": "EPS bearers corresponding to Bearer Contexts to be removed sent in the Modify Bearer Request message. Shall be included if request message contained Bearer Contexts to be removed.For each of those bearers an IE with the same type and instance value shall be included."})
ies.append(
    {"ie_type": "Change Reporting Action", "ie_value": "Change Reporting Action", "presence": "C", "instance": "0",
     "comment": "This IE shall be included with the appropriate Action field If the location Change Reporting mechanism is to be started or stopped for this subscriber in the SGSN/MME."})
ies.append(
    {"ie_type": "CSG Information Reporting Action", "ie_value": "CSG Information Reporting Action", "presence": "CO",
     "instance": "0",
     "comment": "This IE shall be included with the appropriate Action field if the location CSG Info change reporting mechanism is to be started or stopped for this subscriber in the SGSN/MME."})
ies.append({"ie_type": "eNB Information Reporting", "ie_value": "HNB Information Reporting ", "presence": "CO",
            "instance": "0",
            "comment": "This IE shall be included on the S5/S8 and S4/S11 interfaces with the appropriate Action field if H(e)NB information reporting is to be started or stopped for the PDN connection in the SGSN/MME."})
ies.append({"ie_type": "FQDN", "ie_value": "Charging Gateway Name", "presence": "C", "instance": "0",
            "comment": "When Charging Gateway Function (CGF) Address is configured, the PGW shall include this IE on the S5 interface during SGW relocation and when the UE moves from Gn/Gp SGSN to S4-SGSN/MME. See NOTE 1."})
ies.append({"ie_type": "IP Address", "ie_value": "Charging Gateway Address", "presence": "C", "instance": "0",
            "comment": "When Charging Gateway Function (CGF) Address is configured, the PGW shall include this IE on the S5 interface during SGW relocation and when the UE moves from Gn/Gp SGSN to S4-SGSN/MME. See NOTE 1."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "PGW-FQ-CSID", "presence": "C", "instance": "0",
            "comment": "This IE shall be included by PGW on S5/S8and shall be forwarded by SGW on S11 according to the requirements in 3GPP TS 23.007 [17]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "SGW-FQ-CSID", "presence": "C", "instance": "1",
            "comment": "This IE shall be included by SGW on S11 according to the requirements in 3GPP TS 23.007 [17]."})
ies.append({"ie_type": "Recovery", "ie_value": "Recovery", "presence": "C", "instance": "0",
            "comment": "This IE shall be included if contacting the peer for the first time."})
ies.append({"ie_type": "LDN", "ie_value": "SGW LDN", "presence": "O", "instance": "0",
            "comment": "This IE is optionally sent by the SGW to the MME/SGSN on the S11/S4 interfaces (see 3GPP TS 32.423 [44]), when communicating the LDN to the peer node for the first time."})
ies.append({"ie_type": "LDN", "ie_value": "PGW LDN", "presence": "O", "instance": "1",
            "comment": "This IE is optionally sent by the PGW to the SGW on the S5/S8 interfaces (see 3GPP TS 32.423 [44]), when communicating the LDN to the peer node for the first time."})
ies.append({"ie_type": "Indication", "ie_value": "Indication Flags", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included if any one of the applicable flags is set to 1.Applicable flags are:Static IPv4 Address Flag: This flag shall be set to 1 on the S5/S8 interface in the TAU/RAU/Handover with SGW change procedure if the PDP/PDN IPv4 address is static as specified in 3GPP TS 32.251 [8]. See NOTE 3.Static IPv6 Address Flag: This flag shall be set to 1 on the S5/S8 interface in the TAU/RAU/Handover with SGW change procedure if the PDP/PDN IPv6 address is static as specified in 3GPP TS 32.251 [8]. See NOTE 3. PDN Pause Support Indication: this flag shall be set to 1 on the S5/S8 interface during the TAU/RAU/handover with SGW relocation procedures if the PGW supports the PGW Pause of Charging procedure.PDN Pause Enable Indication: this flag shall be set to 1 on the S5/S8 interface during the TAU/RAU/handover with SGW relocation procedures if the PGW enables the new SGW to use the PGW Pause of Charging procedure for this PDN connection. Associate OCI with PGW nodes identity: The PGW shall set this flag to 1 on the S5/S8 interface or S2a/S2b interface if it has included the PGWs Overload Control Information and if this information is to be associated with the node identity (i.e. FQDN or the IP address received from the HSS or DNS during the PGW selection) of the serving PGW. The SGW shall set this flag on the S11/S4 interface if it supports the overload control feature and if the flag is set on the S5/S8 interface.Associate OCI with SGW nodes identity: The SGW shall set this flag to 1 on the S11/S4 interface if it has included the SGWs Overload Control Information and if this information is to be associated with the node identity (i.e. FQDN or the IP address received from the DNS during the SGW selection) of the serving SGW. Delay Tolerant Connection Indication: the flag shall be set to 1 on the S5/S8 interface during a SGW relocation procedure and when the UE moves from Gn/Gp SGSN to S4-SGSN/MME if the PDN connection is Delay Tolerant (see subclause 8.12). See NOTE 9."})
ies.append({"ie_type": "Presence Reporting Area Action", "ie_value": "Presence Reporting Area Action", "presence": "CO",
            "instance": "0",
            "comment": "This IE shall be included on the S5/S8 and S11/S4 interfaces with the appropriate Action field if reporting changes of UE presence in a Presence Routing Area is to be started or stopped for this subscriber in the MME/SGSN."})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "PGW's node level Load Control Information", "presence": "O",
     "instance": "0",
     "comment": "The PGW may include this IE on the S5/S8 or S2a/S2b interface, providing its node level load information, if the load control feature is supported by the PGW and is activated for the PLMN to which the access network node, i.e. MME/S4-SGSN for 3GPP access network, ePDG/TWAN for non-3GPP access network, belongs (see clause 12.2.6)."})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "PGW's APN level Load Control Information", "presence": "O",
     "instance": "1",
     "comment": "The PGW may include this IE on the S5/S8 or S2a/S2b interface, providing APN level load information, if the APN level load control feature is supported by the PGW and is activated for the PLMN to which the access network node, i.e. MME/S4-SGSN for 3GPP access network, ePDG/TWAN for non-3GPP access based network, belongs (see clause 12.2.6).When present, the PGW shall provide one or more instances of this IE, up to maximum of 10, with the same type and instance value, each representing the load information for a list of APN(s).See NOTE 5, NOTE 7."})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "SGW's node level Load Control Information", "presence": "O",
     "instance": "2",
     "comment": "The SGW may include this IE, over the S11/S4 interface if the load control feature is supported by the SGW and is activated in the network (see clause 12.2.6).When present, the SGW shall provide only one instance of this IE, representing its node level load information."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "PGW's Overload Control Information", "presence": "O",
     "instance": "0",
     "comment": "During an overload condition, the PGW may include this IE on the S5/S8 or S2b interface, if the overload control feature is supported by the PGW and is activated for the PLMN to which the access network node, i.e. MME/S4-SGSN for 3GPP access based network, ePDG for non-3GPP access based network, belongs (see clause 12.3.11).When present, the PGW shall provide at least one instance of this IE, representing its overload information. Additionally, the PGW may indicate APN level overload control by providing, one or more instances of this IE, up to maximum of 10, with the same type and instance value, each representing the overload information for a list of APN(s).See NOTE 6, NOTE 8."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "SGW's Overload Control Information", "presence": "O",
     "instance": "1",
     "comment": "During an overload condition, the SGW may include this IE over the S11/S4 interface if the overload control feature is supported by the SGW and is activated in the network (see clause 12.3.11).When present, the SGW shall provide only one instance of this IE, representing its overload information."})
ies.append({"ie_type": "Charging ID", "ie_value": "PDN Connection Charging ID", "presence": "CO", "instance": "0",
            "comment": "The PGW shall include this IE on the S5/S8 interface during a TAU/RAU/HO with SGW relocation procedure, if a PDN connection Charging ID has been allocated during the initial Attach or Initial PDN connection establishment procedure. "})
msg_list[key]["ies"] = ies
