
elsa-auth/psw
=============

[![GoDoc][1]][2]
[![GoCard][3]][4]

[1]: https://godoc.org/github.com/LeKovr/elsa-auth/psw?status.svg
[2]: https://godoc.org/github.com/LeKovr/elsa-auth/psw
[3]: https://goreportcard.com/badge/LeKovr/elsa-auth/psw
[4]: https://goreportcard.com/report/github.com/LeKovr/elsa-auth/psw

[elsa-auth/psw](https://github.com/LeKovr/elsa-auth/psw) - password authentication for [ELSA](https://github.com/LeKovr/elsa) server applications.

## Usage:

```
s := elsa.NewServer()
s.Handle("/api", elsa.APIServer(s.RPC))

app := auth.NewApp(s.DB)
s.RPC.RegisterService(app, "Auth")
s.Handle("/auth", app) // nginx auth subrequest
```
