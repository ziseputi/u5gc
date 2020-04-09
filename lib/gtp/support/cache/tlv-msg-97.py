ies = []
ies.append({"ie_type": "Bearer Context", "ie_value": "Bearer Contexts", "presence": "M", "instance": "0",
            "comment": "This IE shall contain contexts related to bearers that need QoS/TFT modification. Several IEs with this type and instance values shall be included as necessary to represent a list of Bearers. If there is no QoS/TFT modification, only one IE with this type and instance value shall be included."})
ies.append({"ie_type": "PTI", "ie_value": "Procedure Transaction Id", "presence": "C", "instance": "0",
            "comment": "If the request corresponds to UE requested bearer resource modification procedure or the UE requested bearer resource allocation procedure for an E-UTRAN (see NOTE 1) or MS initiated EPS bearer modification procedure, this IE shall be included.PTI shall be the same as the one used in the corresponding Bearer Resource Command"})
ies.append({"ie_type": "PCO", "ie_value": "Protocol Configuration Options", "presence": "C", "instance": "0",
            "comment": "The PGW shall include the Protocol Configuration Options (PCO) IE on the S5/S8 interface, if available and if ePCO is not supported by the UE or the network. The PCO IE shall carry a P-CSCF address list only when the UE is required to perform an IMS registration, e.g during the P-CSCF restoration procedure as defined in clause 5 of 3GPP TS 23.380 [61].If SGW receives this IE, SGW shall forward it to SGSN/MME on the S4/S11 interface."})
ies.append({"ie_type": "AMBR", "ie_value": "Aggregate Maximum Bit Rate", "presence": "M", "instance": "0",
            "comment": "APN-AMBR"})
ies.append(
    {"ie_type": "Change Reporting Action", "ie_value": "Change Reporting Action", "presence": "C", "instance": "0",
     "comment": "This IE shall be included on the S5/S8 and S4/S11 interfaces with the appropriate Action field If the location Change Reporting mechanism is to be started or stopped for this subscriber in the SGSN/MME."})
ies.append(
    {"ie_type": "CSG Information Reporting Action", "ie_value": "CSG Information Reporting Action", "presence": "CO",
     "instance": "0",
     "comment": "This IE shall be included on the S5/S8 and S4/S11 interfaces with the appropriate Action field if the CSG Info reporting mechanism is to be started or stopped for this subscriber in the SGSN/MME."})
ies.append({"ie_type": "eNB Information Reporting", "ie_value": "HNB Information Reporting ", "presence": "CO",
            "instance": "0",
            "comment": "This IE shall be included on the S5/S8 and S4/S11 interfaces with the appropriate Action field if H(e)NB information reporting is to be started or stopped for the PDN connection in the SGSN/MME."})
ies.append({"ie_type": "Indication", "ie_value": "Indication flags", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included if any one of the applicable flags is set to 1.Applicable flags are:Retrieve Location Indication: This flag shall be set to 1 on the S5/S8, S4/S11, S2a and S2b interfaces in the PGW Initiated Bearer Modification procedure if the location information is requested. Associate OCI with PGW nodes identity: The PGW shall set this flag to 1 on the S5/S8 interface or S2a/S2b interface if it has included the PGWs Overload Control Information and if this information is to be associated with the node identity (i.e. FQDN or the IP address received from the HSS or DNS during the PGW selection) of the serving PGW. The SGW shall set this flag on the S11/S4 interface if it supports the overload control feature and if the flag is set on the S5/S8 interface.Associate OCI with SGW nodes identity: The SGW shall set this flag to 1 on the S11/S4 interface if it has included the SGWs Overload Control Information and if this information is to be associated with the node identity (i.e. FQDN or the IP address received from the DNS during the SGW selection) of the serving SGW."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "PGW-FQ-CSID", "presence": "C", "instance": "0",
            "comment": "This IE shall be included by PGW on the S5/S8 and S2a/S2b interfaces,  and when received from S5/S8 be forwarded by SGW on S11 according to the requirements in 3GPP TS 23.007 [17]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "SGW-FQ-CSID", "presence": "C", "instance": "1",
            "comment": "This IE shall be included by SGW on S11 according to the requirements in 3GPP TS 23.007 [17]."})
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
     "comment": "The PGW may include this IE on the S5/S8 or S2a/S2b interface, providing APN level load information, if the APN level load control feature is supported by the PGW and is activated for the PLMN to which the access network node, i.e. MME/S4-SGSN for 3GPP access network, ePDG/TWAN for non-3GPP access based network, belongs (see clause 12.2.6).When present, the PGW shall provide one or more instances of this IE, up to maximum of 10, with the same type and instance value, each representing the load information for a list of APN(s).See NOTE 2, NOTE 4."})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "SGW's node level Load Control Information", "presence": "O",
     "instance": "2",
     "comment": "The SGW may include this IE, over the S11/S4 interface if the load control feature is supported by the SGW and is activated in the network (see clause 12.2.6).When present, the SGW shall provide only one instance of this IE, representing its node level load information."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "PGW's Overload Control Information", "presence": "O",
     "instance": "0",
     "comment": "During an overload condition, the PGW may include this IE on the S5/S8 or S2a/S2b interface, if the overload control feature is supported by the PGW and is activated for the PLMN to which the access network node, i.e. MME/S4-SGSN for 3GPP access based network, ePDG/TWAN for non-3GPP access based network, belongs (see clause 12.3.11).When present, the PGW shall provide at least one instance of this IE, representing its overload information. Additionally, the PGW may indicate APN level overload control by providing, one or more instances of this IE, up to maximum of 10, with the same type and instance value, each representing the overload information for a list of APN(s).See NOTE 3, NOTE 5."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "SGW's Overload Control Information", "presence": "O",
     "instance": "1",
     "comment": "During an overload condition, the SGW may include this IE over the S11/S4 interface if the overload control feature is supported by the SGW and is activated in the network (see clause 12.3.11).When present, the SGW shall provide only one instance of this IE, representing its overload information."})
ies.append({"ie_type": "F-Container", "ie_value": "NBIFOM Container", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included on the S5/S8 or S2a/S2b interfaces if the PGW needs to send NBIFOM information as specified in 3GPP TS 23.161 [71]. The Container Type shall be set to 4."})
msg_list[key]["ies"] = ies
