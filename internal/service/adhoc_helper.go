package service

func adHocMatches(v AdHocView, q AdHocQuery, reqID string) bool {
	return v.RequestID == reqID &&
		v.AtSeconds == q.AtSeconds &&
		v.Query.QName == q.Query.QName &&
		v.Query.QType == q.Query.QType
}
