package lldp

// LLDP Port ID subtype enumerations (LLDP-MIB). Distinct from Chassis ID
// subtypes. Only these values are valid for lldpLocPortIdSubtype and
// lldpRemPortIdSubtype.
const (
	PortSubtypeInterfaceAlias = 1
	PortSubtypePortComponent  = 2
	PortSubtypeMACAddress     = 3
	PortSubtypeNetworkAddress = 4
	PortSubtypeInterfaceName  = 5
	PortSubtypeAgentCircuitID = 6
	PortSubtypeLocal          = 7
)

// Chassis ID subtype enumerations. MAC=4, networkAddress=5, interfaceName=6,
// local=7.
const (
	ChassisSubtypeChassisComponent = 1
	ChassisSubtypeInterfaceAlias   = 2
	ChassisSubtypePortComponent    = 3
	ChassisSubtypeMACAddress       = 4
	ChassisSubtypeNetworkAddress   = 5
	ChassisSubtypeInterfaceName    = 6
	ChassisSubtypeLocal            = 7
)

// Admin status values for lldpPortConfigAdminStatus.
const (
	AdminStatusTxOnly   = 1
	AdminStatusRxOnly   = 2
	AdminStatusTxAndRx  = 3
	AdminStatusDisabled = 4
)

// IfType ethernetCsmacd is the physical Ethernet port candidate.
const IfTypeEthernetCsmacd = 6
