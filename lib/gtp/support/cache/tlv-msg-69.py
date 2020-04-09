ies = []
ies.append({"ie_type": "Cause", "ie_value": "Cause", "presence": "M", "instance": "0", "comment": ""})
ies.append({"ie_type": "EBI", "ie_value": "Linked EPS Bearer ID", "presence": "M", "instance": "0",
            "comment": "See subclause 6.1.1 Presence requirements of Information Elements."})
ies.append({"ie_type": "PTI", "ie_value": "Procedure Transaction ID", "presence": "M", "instance": "0",
            "comment": "See subclause 6.1.1 Presence requirements of Information Elements."})
ies.append({"ie_type": "Indication", "ie_value": "Indication Flags", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included if any one of the applicable flags is set to 1.Applicable flags are:Associate OCI with PGW nodes identity: The PGW shall set this flag to 1 on the S5/S8 interface or S2a/S2b interface if it has included the PGWs Overload Control Information and if this information is to be associated with the node identity (i.e. FQDN or the IP address received from the HSS or DNS during the PGW selection) of the serving PGW. The SGW shall set this flag on the S11/S4 interface if it supports the overload control feature and if the flag is set on the S5/S8 interface.Associate OCI with SGW nodes identity: The SGW shall set this flag to 1 on the S11/S4 interface if it has included the SGWs Overload Control Information and if this information is to be associated with the node identity (i.e. FQDN or the IP address received from the DNS during the SGW selection) of the serving SGW."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "PGW's Overload Control Information", "presence": "O",
     "instance": "0",
     "comment": "During an overload condition, the PGW may include this IE on the S5/S8, if the overload control feature is supported by the PGW and is activated for the PLMN to which the access network node, i.e. MME/S4-SGSN for 3GPP access based network, belongs (see clause 12.3.11).When present, the PGW shall provide at least one instance of this IE, representing its overload information. Additionally, the PGW may indicate APN level overload control by providing, one or more instances of this IE, up to maximum of 10, with the same type and instance value, each representing the overload information for a list of APN(s).See NOTE 1, NOTE 2."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "SGW's Overload Control Information", "presence": "O",
     "instance": "1",
     "comment": "During an overload condition, the SGW may include this IE over the S11/S4 interface if the overload control feature is supported by the SGW and is activated in the network (see clause 12.3.11).When present, the SGW shall provide only one instance of this IE, representing its overload information."})
ies.append({"ie_type": "Recovery", "ie_value": "Recovery", "presence": "O", "instance": "0", "comment": ""})
ies.append({"ie_type": "F-Container", "ie_value": "NBIFOM Container", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included on the S5/S8 or S2a/S2b interfaces if the PGW needs to send NBIFOM information as specified in 3GPP TS 23.161 [71]. The Container Type shall be set to 4."})
msg_list[key]["ies"] = ies
