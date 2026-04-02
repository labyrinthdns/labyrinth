package dns

// UnpackQuestion decodes a question entry from the wire format.
func UnpackQuestion(msg []byte, offset int) (Question, int, error) {
	var q Question
	var err error

	q.Name, offset, err = DecodeName(msg, offset)
	if err != nil {
		return q, 0, err
	}

	r := &wireReader{buf: msg, offset: offset}
	if q.Type, err = r.readUint16(); err != nil {
		return q, 0, err
	}
	if q.Class, err = r.readUint16(); err != nil {
		return q, 0, err
	}

	return q, r.offset, nil
}
