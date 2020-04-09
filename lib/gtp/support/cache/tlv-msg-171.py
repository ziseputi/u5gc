ies = []
ies.append({"ie_type": "Cause", "ie_value": "Cause", "presence": "M", "instance": "0", "comment": ""})
ies.append({"ie_type": "Recovery", "ie_value": "Recovery", "presence": "O", "instance": "0",
            "comment": "This IE shall be included if contacting the peer for the first time"})
ies.append({"ie_type": "Indication", "ie_value": "Indication Flags", "presence": "CO", "instance": "0",
            "comment": "This IE shall be included if any one of the applicable flags is set to 1.Applicable flags are:Associate OCI with SGW nodes identity: The SGW shall set this flag to 1 on the S11/S4 interface if it has included the SGWs Overload Control Information and if this information is to be associated with the node identity (i.e. FQDN or the IP address received from the DNS during the SGW selection) of the serving SGW."})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "SGW's node level Load Control Information", "presence": "O",
     "instance": "0",
     "comment": "The SGW may include this IE, over the S11/S4 interface if the load control feature is supported by the SGW and is activated in the network (see clause 12.2.6).When present, the SGW shall provide only one instance of this IE, representing its node level load information."})
ies.append(
    {"ie_type": "Overload Control Information", "ie_value": "SGW's Overload Control Information", "presence": "O",
     "instance": "0",
     "comment": "During an overload condition, the SGW may include this IE over the S11/S4 interface if the overload control feature is supported by the SGW and is activated in the network (see clause 12.3.11).When present, the SGW shall provide only one instance of this IE, representing its overload information."})
msg_list[key]["ies"] = ies
