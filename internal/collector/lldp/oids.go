// Package lldp defines the numeric OIDs and pure parsing functions for the
// standard LLDP-MIB, IF-MIB and BRIDGE-MIB objects required by M1. Parsing is
// transport-independent so fixtures can be replayed without a live device.
package lldp

// System group (1.3.6.1.2.1.1).
const (
	SysDescr    = "1.3.6.1.2.1.1.1.0"
	SysObjectID = "1.3.6.1.2.1.1.2.0"
	SysUpTime   = "1.3.6.1.2.1.1.3.0"
	SysName     = "1.3.6.1.2.1.1.5.0"
)

// LLDP-MIB, base L = 1.0.8802.1.1.2.1.
const (
	LldpStatsRemTablesLastChangeTime = "1.0.8802.1.1.2.1.2.1.0"
	LldpLocChassisIDSubtype          = "1.0.8802.1.1.2.1.3.1.0"
	LldpLocChassisID                 = "1.0.8802.1.1.2.1.3.2.0"
	LldpLocSysCapSupported           = "1.0.8802.1.1.2.1.3.5.0"
	LldpLocSysCapEnabled             = "1.0.8802.1.1.2.1.3.6.0"
	LldpPortConfigAdminStatus        = "1.0.8802.1.1.2.1.1.6.1.2"

	LldpLocPortTable     = "1.0.8802.1.1.2.1.3.7"
	LldpLocPortIDSubtype = "1.0.8802.1.1.2.1.3.7.1.2"
	LldpLocPortID        = "1.0.8802.1.1.2.1.3.7.1.3"
	LldpLocPortDesc      = "1.0.8802.1.1.2.1.3.7.1.4"

	LldpRemTable            = "1.0.8802.1.1.2.1.4.1"
	LldpRemChassisIDSubtype = "1.0.8802.1.1.2.1.4.1.1.4"
	LldpRemChassisID        = "1.0.8802.1.1.2.1.4.1.1.5"
	LldpRemPortIDSubtype    = "1.0.8802.1.1.2.1.4.1.1.6"
	LldpRemPortID           = "1.0.8802.1.1.2.1.4.1.1.7"
	LldpRemPortDesc         = "1.0.8802.1.1.2.1.4.1.1.8"
	LldpRemSysName          = "1.0.8802.1.1.2.1.4.1.1.9"
	LldpRemSysDesc          = "1.0.8802.1.1.2.1.4.1.1.10"
	LldpRemSysCapSupported  = "1.0.8802.1.1.2.1.4.1.1.11"
	LldpRemSysCapEnabled    = "1.0.8802.1.1.2.1.4.1.1.12"

	LldpRemManAddrTable     = "1.0.8802.1.1.2.1.4.2"
	LldpRemManAddrIfSubtype = "1.0.8802.1.1.2.1.4.2.1.3"
)

// IF-MIB (1.3.6.1.2.1.2.2.1 and 1.3.6.1.2.1.31.1.1.1).
const (
	IfTable       = "1.3.6.1.2.1.2.2.1"
	IfIndex       = "1.3.6.1.2.1.2.2.1.1"
	IfDescr       = "1.3.6.1.2.1.2.2.1.2"
	IfType        = "1.3.6.1.2.1.2.2.1.3"
	IfPhysAddress = "1.3.6.1.2.1.2.2.1.6"
	IfName        = "1.3.6.1.2.1.31.1.1.1.1"
	IfAlias       = "1.3.6.1.2.1.31.1.1.1.18"
)

// BRIDGE-MIB (1.3.6.1.2.1.17), optional port→ifIndex assist.
const (
	Dot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2"
)
