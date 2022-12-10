const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/authorize', (req, res) => {
	const reqID = randomString();
	requests[reqID] = req.query;
	const clientId = req.query.client_id;
	if (!clients[clientId]) {
		res.status(401).end();
	}
	if(req.query.scope) {
		const reqScopes = req.query.scope?.split(" ");
		if (!containsAll(clients[clientId]?.scopes, reqScopes)) {
			res.status(401).end();
		} else {
			const params = {
				client: clients[clientId],
				scope: req.query.scope,
				requestId: reqID
			}
			res.render("login", params);
		}
	}
  })

app.post('/approve', (req, res) => {
	const username = req.body.userName;
	const password = req.body.password;
	const reqId = req.body.requestId;
	if (users[username] === password && requests[reqId]) {
		const userRequest = requests[reqId];
		delete requests[reqId];
		const randomStr = randomString();
		authorizationCodes[randomStr] = {
			clientReq: userRequest,
			userName: username
		}
		const params = new URLSearchParams({
			code: randomStr,
			state: userRequest.state,
		  });
		res.redirect(302, `${userRequest.redirect_uri}?${params}`)
	} else {
		res.status(401).end();
	}
})

app.post('/token', (req, res) => {
	let obj = {};
	if(!req.headers.authorization) {
		res.status(401).end();
	} else {
		const authHeaders = decodeAuthCredentials(req.headers.authorization);
		const { clientId, clientSecret } = authHeaders;
		if (!clients[clientId]?.clientSecret === clientSecret) {
			res.status(401).end();
		} else {
			if (!authorizationCodes[req.body.code]) {
				res.status(401).end();
			} else {
				obj = authorizationCodes[req.body.code];
				delete authorizationCodes[req.body.code];
				const token = jwt.sign({ "userName": obj.userName, "scope": obj.clientReq?.scope}, config.privateKey, { algorithm: 'RS256'});
				const response = {"access_token": token, "token_type": "Bearer"}
				res.status(200).json(response);
			}
		}
	}	
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
