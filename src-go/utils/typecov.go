package utils

func I8ToStr(input []int8) string {
	data := make([]byte, 0)
	for _, v := range input {
		if v == int8(0) {
			break
		}
		data = append(data, byte(v))
	}
	return string(data)
}
