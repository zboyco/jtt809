package jtt809

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// BatchLocationRecord 表示补报的一条定位记录。
type BatchLocationRecord struct {
	Position *VehiclePosition
}

// BatchLocationUpload 表示主链路车辆定位信息自动补报（0x1200 子业务 0x1203）。
// 按规范单包 GNSSCount 建议 1-5 条。
type BatchLocationUpload struct {
	VehicleNo    string
	VehicleColor PlateColor
	Locations    []BatchLocationRecord
}

func (BatchLocationUpload) MsgID() uint16 { return MsgIDDynamicInfo }

// Encode 构造 0x1203 子业务载荷，并封装到 0x1200 主链路报文。
func (v BatchLocationUpload) Encode() ([]byte, error) {
	if len(v.VehicleNo) == 0 {
		return nil, errors.New("vehicle number is required")
	}
	if len(v.Locations) == 0 {
		return nil, errors.New("at least one location is required")
	}
	if len(v.Locations) > 255 {
		return nil, errors.New("location count exceeds 255")
	}

	var buf bytes.Buffer
	buf.WriteByte(byte(len(v.Locations)))
	for _, loc := range v.Locations {
		locBytes, err := encodeBatchLocationBody(loc)
		if err != nil {
			return nil, err
		}
		buf.Write(locBytes)
	}

	// 补报需要包含车牌和颜色，虽然协议中可能隐含在头部，但此处作为子业务体的一部分
	// 注意：标准协议中 0x1203 的子业务体结构可能不同，这里假设与 0x1202 类似但包含多条
	// 实际上 0x1203 通常是：车牌(21)+颜色(1)+数量(1)+N*定位数据
	// 这里我们需要重新构建 buffer 以符合这种结构
	var finalBuf bytes.Buffer
	finalBuf.Write(PadRightGBK(v.VehicleNo, 21))
	finalBuf.WriteByte(byte(v.VehicleColor))
	finalBuf.Write(buf.Bytes())

	const subMsgID uint16 = SubMsgBatchLocation
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, subMsgID)
	_ = binary.Write(&out, binary.BigEndian, uint32(finalBuf.Len()))
	out.Write(finalBuf.Bytes())
	return out.Bytes(), nil
}

func encodeBatchLocationBody(loc BatchLocationRecord) ([]byte, error) {
	if loc.Position == nil {
		return nil, errors.New("vehicle position is required")
	}
	return loc.Position.encode()
}
