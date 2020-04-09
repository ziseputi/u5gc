ies = []
ies.append({"ie_type": "Cause", "ie_value": "Cause", "presence": "C", "instance": "0",
            "comment": "If ISR is being de-activated, the Cause IE shall be included on the S4/S11 interface with the value ISR deactivation, which indicates that the SGW shall delete the bearer resources by sending Delete Bearer Request to the MME/SGSN on which ISR was activated with the same Cause value ISR deactivation. See NOTE 3"})
ies.append({"ie_type": "EBI", "ie_value": "Linked EPS Bearer ID", "presence": "C", "instance": "0",
            "comment": "This IE shall be included on the S4/S11, S5/S8 and S2a/S2b interfaces to indicate the default bearer associated with the PDN being disconnected unless in the handover/TAU/RAU with SGW relocation procedures."})
ies.append({"ie_type": "ULI", "ie_value": "User Location Information", "presence": "C", "instance": "0",
            "comment": "The MME/SGSN shall include this IE on the S4/S11 interface for the Detach procedure. The MME shall include ECGI, SGSN shall include CGI/SAI. The SGW shall include this IE on S5/S8 if it receives the ULI from MME/SGSN. See NOTE 4."})
ies.append({"ie_type": "Indication", "ie_value": "Indication Flags", "presence": "C", "instance": "0",
            "comment": "This IE shall be included if any one of the applicable flags is set to 1.Applicable flags:Operation Indication: This flag shall be set to 1 over S4/S11 interface, if the SGW needs to forward the Delete Session Request message to the PGW. This flag shall not be set if the ISR associated GTP entity sends this message to the SGW in the Detach procedure. This flag shall also not be set to 1 in the SRNS Relocation Cancel Using S4 (6.9.2.2.4a in 3GPP TS 23.060 [4]), Inter RAT handover Cancel procedure with SGW change TAU with Serving GW change, Gn/Gb based RAU (see 5.5.2.5, 5.3.3.1, D.3.5 in 3GPP TS 23.401 [3], respectively), S1 Based handover Cancel procedure with SGW change.This flag shall also not be set to 1 for, e.g., X2 based handover procedure with SGW change(see subclause 5.5.1.1.3 in 3GPP TS 23.401 [3]), or S1 based handover procedure with SGW change (see subclause 5.5.1.2.2 in 3GPP TS 23.401 [3]). See NOTE 1.Scope Indication: This flag shall be set to 1 on the S4/S11 interface, if the request corresponds to TAU/RAU/Handover with SGW change/SRNS Relocation Cancel Using S4 with SGW change, Inter RAT handover Cancel procedure with SGW change, S1 Based handover Cancel procedure with SGW change. See NOTE 1.Release Over Any Access Indication (ROAAI): This flag shall be set to 1 over the S4/S11 interface when an NB-IFOM capable MME/SGSN wishes to request release of the PDN connection over any applicable access, e.g.:during a basic P-CSCF restoration procedure; or when the MME/SGSN wishes that the PDN connection be reestablished via another PGW for SIPTO.See NOTE 9."})
ies.append({"ie_type": "PCO", "ie_value": "Protocol Configuration Options", "presence": "C", "instance": "0",
            "comment": "If the UE includes the PCO IE, then the MME/SGSN shall copy the content of this IE transparently from the PCO IE included by the UE.If SGW receives the PCO IE, SGW shall forward it to PGW."})
ies.append({"ie_type": "Node Type", "ie_value": "Originating Node", "presence": "C", "instance": "0",
            "comment": "This IE shall be included on the S4/S11 interface if the ISR is active in MME/SGSN to denote the type of the node originating the message.The SGW shall release the corresponding Originating Node related EPS Bearer contexts information in the PDN Connection identified by the LBI."})
ies.append({"ie_type": "F-TEID", "ie_value": "Sender F-TEID for Control Plane", "presence": "O", "instance": "0",
            "comment": "This IE may be included on the S4/S11 interfaces except when the source MME/SGSN initiates the deletion of PDN connections not supported by the target MME/SGSN during a successful handover/TAU/RAU procedure with MME/SGSN change and without SGW change (see subclauses 5.3.3.2 and 5.5.1.2.1 of 3GPP TS 23.401 [3]), in which case this IE shall not be included. See NOTE 10.If the Sender F-TEID for Control Plane is received by the SGW, the SGW shall only accept the Delete Session Request message when the Sender F-TEID for Control Plane in this message is the same as the Sender F-TEID for Control Plane that was last received in either the Create Session Request message or the Modify Bearer Request message on the given interface. If the ISR is activated, two F-TEIDs exist: one for the MME and the other for the SGSN. See NOTE 2."})
ies.append({"ie_type": "UE Time Zone", "ie_value": "UE Time Zone", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included by the MME on the S11 interface or by the SGSN on the S4 interface, for Detach and PDN Disconnection procedures, if the UE Time Zone has changed."})
ies.append({"ie_type": "ULI Timestamp", "ie_value": "ULI Timestamp", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included on the S4/S11 interface if the ULI IE is present. It indicates the time when the User Location Information was acquired. The SGW shall include this IE on S5/S8 if the SGW receives it from the MME/SGSN. See NOTE 4."})
ies.append({"ie_type": "RAN/NAS Cause", "ie_value": "RAN/NAS Release Cause", "presence": "CO", "instance": "0",
            "comment": "The MME shall include this IE on the S11 interface to indicate the NAS release cause to release the PDN connection, if available and this information is permitted to be sent to the PGW operator according to MME operators policy. The SGW shall include this IE on the S5/S8 interface if it receives it from the MME and if the Operation Indication bit received from the MME is set to 1."})
ies.append({"ie_type": "TWAN Identifier", "ie_value": "TWAN Identifier", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included by the TWAN on the S2a interface as specified in 3GPP TS 23.402 [45]. "})
ies.append(
    {"ie_type": "TWAN Identifier Timestamp", "ie_value": "TWAN Identifier Timestamp", "presence": "CO", "instance": "0",
     "comment": "This IE shall be included by the TWAN on the S2a if the TWAN Identifier IE is present. It shall indicate the time when the TWAN acquired the TWAN Identifier information. "})
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
ies.append({"ie_type": "TWAN Identifier", "ie_value": "WLAN Location Information", "presence": "CO", "instance": "1",
            "comment": "The ePDG shall include this IE on the S2b interface if the WLAN Location Information is available. "})
ies.append(
    {"ie_type": "TWAN Identifier Timestamp", "ie_value": "WLAN Location Timestamp", "presence": "CO", "instance": "1",
     "comment": "The ePDG shall include this IE on the S2b interface, if the WLAN Location Timestamp is available. "})
ies.append({"ie_type": "IP Address", "ie_value": "UE Local IP Address", "presence": "CO", "instance": "0",
            "comment": "The ePDG shall include this IE on the S2b interface. "})
ies.append({"ie_type": "Port Number", "ie_value": "UE UDP Port", "presence": "CO", "instance": "0",
            "comment": "The ePDG shall include this IE on the S2b interface if NAT is detected and UDP encapsulation is used."})
ies.append({"ie_type": "ePCO", "ie_value": "Extended Protocol Configuration Options", "presence": "CO", "instance": "0",
            "comment": "If the UE includes the ePCO IE, then the MME shall copy the content of this IE transparently from the ePCO IE included by the UE.If the SGW receives the ePCO IE, the SGW shall forward it to the PGW."})
ies.append({"ie_type": "Port Number", "ie_value": "UE TCP Port", "presence": "CO", "instance": "1",
            "comment": "The ePDG shall include this IE on the S2b interface if NAT is detected and the TCP encapsulation is used."})
msg_list[key]["ies"] = ies
