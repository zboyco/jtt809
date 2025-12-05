package jtt809

// HeartbeatRequest 表示主链路连接保持请求（0x1005），业务体为空。
type HeartbeatRequest struct{}

func (HeartbeatRequest) MsgID() uint16 { return MsgIDHeartbeatRequest }
func (HeartbeatRequest) Encode() ([]byte, error) {
	return []byte{}, nil
}

// HeartbeatResponse 表示主链路连接保持应答（0x1006），业务体为空。
type HeartbeatResponse struct{}

func (HeartbeatResponse) MsgID() uint16 { return MsgIDHeartbeatResponse }
func (HeartbeatResponse) Encode() ([]byte, error) {
	return []byte{}, nil
}
