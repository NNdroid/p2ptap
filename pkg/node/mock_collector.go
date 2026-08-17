package node

import (
	"net"

	"p2ptap/pkg/observer"
)

// noopCollector is a no-op implementation of observer.Collector used when no
// concrete web collector is injected (e.g. tests, or nodes started without a
// WebUI). It satisfies the full interface but discards every call.
type noopCollector struct{}

func (noopCollector) RecordSent(int)                                                        {}
func (noopCollector) RecordRecv(int)                                                        {}
func (noopCollector) RecordPacketDir([]byte, bool)                                          {}
func (noopCollector) RecordFrame([]byte)                                                    {}
func (noopCollector) RecordDedup()                                                          {}
func (noopCollector) RecordPeerDedup(string)                                                {}
func (noopCollector) RecordTxSeq(string, uint64)                                            {}
func (noopCollector) RecordRxSeq(string, uint64, uint64, uint64, uint64, float64)           {}
func (noopCollector) RecordGatewayPacket()                                                  {}
func (noopCollector) RecordNDP()                                                            {}
func (noopCollector) RecordProtocol(uint16)                                                 {}
func (noopCollector) CaptureFrame(observer.FrameDirection, []byte)                          {}
func (noopCollector) CaptureFrameWithPeers(observer.FrameDirection, []byte, string, string) {}
func (noopCollector) SetNodeInfo(string, string, string, string, string)                    {}
func (noopCollector) SetSecurity(string, string, string)                                    {}
func (noopCollector) SetPeerEncryption([]observer.PeerObfInfoDTO)                           {}
func (noopCollector) SetTAPState(*observer.TAPStateDTO)                                     {}
func (noopCollector) SetTAPSelfTest(func() map[string]interface{})                          {}
func (noopCollector) SetPeerResolver(func(net.HardwareAddr) string)                         {}
func (noopCollector) SetCallbacks(observer.CollectorConfig)                                 {}
func (noopCollector) GetTxRxStats() observer.TxRxStats                                      { return observer.TxRxStats{} }
func (noopCollector) UpdatePeers([]observer.PeerInfoDTO)                                    {}
func (noopCollector) UpdateMACTable([]observer.MACInfoDTO)                                  {}
func (noopCollector) UpdateARPTable([]observer.ARPInfoDTO)                                  {}
func (noopCollector) UpdateIPTable([]observer.IPInfoDTO)                                    {}
func (noopCollector) UpdateRoutes([]observer.RouteInfoDTO)                                  {}
func (noopCollector) UpdateSubnetRoutes([]observer.SubnetRouteDTO)                          {}
func (noopCollector) UpdatePeerMetas([]observer.PeerMetaDTO)                                {}
func (noopCollector) UpdateMeshMatrix([]observer.MeshMatrixCellDTO)                         {}
func (noopCollector) UpdateProtocolChannels([]observer.ProtocolChannelDTO)                 {}
func (noopCollector) UpdateActiveStreams([]observer.ProtocolStreamDTO)                     {}
func (noopCollector) UpdateDuplicateIPConflicts([]observer.DuplicateIPConflictDTO)          {}
func (noopCollector) UpdateListenAddrs([]string)                                            {}
func (noopCollector) UpdateNATStatus(string)                                                {}
func (noopCollector) UpdateExitNode(observer.ExitNodeInfoDTO)                               {}
func (noopCollector) PeekPeerID(string) (string, bool)                                      { return "", false }
func (noopCollector) SetDispatchDrops(uint64)                                               {}
func (noopCollector) GetACLStats() observer.ACLStatsDTO                                     { return observer.ACLStatsDTO{} }
func (noopCollector) GetResponse() observer.StatsResponse                                   { return observer.StatsResponse{} }

// ensure noopCollector satisfies observer.Collector at compile time.
var _ observer.Collector = noopCollector{}
