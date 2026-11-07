package webui

import "gonet/internal/store/postgres"

type linkEndpoint struct {
	DisplayName          string  `json:"display_name,omitempty"`
	DeviceID             string  `json:"device_id"`
	InterfaceName        *string `json:"interface_name"`
	InterfaceDescription *string `json:"interface_description"`
	IfIndex              *int32  `json:"if_index"`
	InterfaceNameSource  *string `json:"interface_name_source"`
	IfIndexStatus        string  `json:"if_index_status"`
}

func projectLinkEndpoint(deviceID int64, evidence postgres.LinkEndpointEvidence) linkEndpoint {
	out := linkEndpoint{DeviceID: idString(deviceID), InterfaceDescription: evidence.IfAlias, IfIndexStatus: "unknown"}
	if evidence.IfIndex != nil && *evidence.IfIndex > 0 {
		out.IfIndex, out.IfIndexStatus = evidence.IfIndex, "known"
	}
	if evidence.IfName != nil && *evidence.IfName != "" {
		source := "if_name"
		out.InterfaceName, out.InterfaceNameSource = evidence.IfName, &source
	} else if evidence.LLDPInterfaceName != nil && *evidence.LLDPInterfaceName != "" {
		source := "lldp_interface_name"
		out.InterfaceName, out.InterfaceNameSource = evidence.LLDPInterfaceName, &source
	}
	return out
}
