package jtt809

// SimpleAuthValidator 仅用于测试场景的固定账号/密码/接入码鉴权器。
func SimpleAuthValidator(expectedUser uint32, expectedPassword string, expectedGnssCenterID uint32, verifyCode uint32) AuthValidator {
	return func(req LoginRequest) (LoginResponse, error) {
		if req.UserID != expectedUser {
			return LoginResponse{Result: LoginUnregistered, VerifyCode: verifyCode}, nil
		}
		if req.GnssCenterID != expectedGnssCenterID {
			return LoginResponse{Result: LoginGnssCenterIDError, VerifyCode: verifyCode}, nil
		}
		if req.Password != expectedPassword {
			return LoginResponse{Result: LoginPasswordError, VerifyCode: verifyCode}, nil
		}
		return LoginResponse{Result: LoginOK, VerifyCode: verifyCode}, nil
	}
}
