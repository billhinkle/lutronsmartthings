// v 1.1.0  original master	nate schwartz
// v 2018.01.03 13:00UTC	wjh
//	cleaned up some SmartThings comm, added self-identifying ST IP support
//	overrode express error handler transmission so SmartThings hub only sees a 500 Server Error now, not stack trace
//	dynamically select first free port from 5000 for SmartThings requests
//	modified ssdp advertisement:
//		start ssdp advertisement only after everything else initialized
//		advertises dynamically selected port (5000+),
//		advertises device-unique USN (uuid),
//		location is /connect 'til 1st ST get/post, then /status so ST hub sees our restart & maybe IP/port change
//
//	added handling of multi-line telnet bursts (as in reply to scene requests via telnet)
//	added attempt to gracefully logout the bridge's telnet at shutdown or comm retry
//	restored  ST status/refresh checking for LC Pro bridge via telnet
//	restored  ST scene triggering for LC Pro bridge via telnet
//	modified SmartThings command responses to handle via Telnet if available, else SSL
//	added auto resume for tls/SSL connection to LC bridges, removed SSH references
//	added auto reconnect for tls/SSL and telnet connection to LC bridges on expected reply timeout & comm errors
//	added 1-minute ping watchdog to monitor LC bridge connection (via SSL or Telnet for Pro)
//	      ping watchdog is defered when expecting a status response, since the (Telnet) ping response may corrupt it
//	added support for multiple pico button press/held/ramp events in play simultaneously (can the LC bridge do that?)
//	added pseudo-release for pico buttons after timeout (buttons 1,2,3 won't release after ~6 sec)
//	added (partial!) support for PJ2-4B Pico (4-buttons: codes 8,9,10,11)... need more config info!
//	modified LIP-to-LEAP device matching to also require Area match if Area is defined in LIP data (w/ Name)
//	clarified some nomenclature, method, function and variable names, refactored some calling schemas
'use strict';

const assert = require('assert');
const net = require('net');
const getport = require('getport');
const request = require('request');
const express = require('express');
const bodyParser  = require('body-parser');
const tls = require('tls');
const ssdpServer = require('node-ssdp').Server;
const uuidv1 = require('uuid/v1');
const ip = require('ip');
const ipaddr = require('ipaddr.js');
const mDNSHandler = require('bonjour')();
const eventEmitter = require('events');
const fs = require('fs');
// var cmd = require('node-cmd');
// var CronJob = require('cron').CronJob;
const forge = require('node-forge');
const URLSearchParams = require('url-search-params');

// #ifdef TelnetDebug
// for telnet debug, type @something at the console and it will be relayed to the Telnet interface, if connected
const readline = require('readline');
const telnetConsoleRL = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  // prompt: 'PRO> '
});
telnetConsoleRL.on('SIGINT', function () {
  process.emit('SIGINT');
});
// #endif

const CLIENT_ID = "e001a4471eb6152b7b3f35e549905fd8589dfcf57eb680b6fb37f20878c28e5a";
const CLIENT_SECRET = "b07fee362538d6df3b129dc3026a72d27e1005a3d1e5839eed5ed18c63a89b27";
const REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob";

const app = express();
app.use(bodyParser.json());

var exports = module.exports = {};

var overrideNoPro = false;	// command-line flag to ignore Pro-ness of the bridge(s)

var lutronBridge = [];		// per-bridge objects array
var lutronBridgeSN = {};	// SN-to-bridge index lookup
var lutronBridgeEvents = new eventEmitter();
const LBE_GOTDEVICES = 'gotdevices';
const LBE_GOTSCENES = 'gotscenes';

const communiqueBridgePingRequest    = '{"CommuniqueType":"ReadRequest","Header":{"Url":"/server/status/ping"}}\n';
const communiqueBridgeDevicesRequest = '{"CommuniqueType":"ReadRequest","Header":{"Url":"/device"}}\n';
const communiqueBridgeScenesRequest  = '{"CommuniqueType":"ReadRequest","Header":{"Url":"/virtualbutton"}}\n';
const communiqueBridgeLIPDevicesRequest  = '{"CommuniqueType":"ReadRequest","Header":{"Url":"/server/2/id"}}\n';

const LCB_RESPONSE_TIMEOUT = 3000;
const LCB_RECONNECT_DELAY = 7500;
const LCB_PING_INTERVAL = 90000;

const DEFAULT_REQST_PORT = 5000;
const STLAN_PORT = 39500;	// this could be (re-)set dynammically upon ST IP acquistion via /connect

// ????? temporary mac handler
var sb_mac = [];

var SMARTBRIDGE_IP;
var SMARTTHINGS_IP;
var stReqPort = DEFAULT_REQST_PORT;
var stReqServer = null;
var ssdp = null;

var picoButtonMethods = [];
var picoHeldTimeout = 6050; //milliseconds
var picoShortPressTime;
var picoIntervalTime;
var picoActive = {};		// list object of active picos keyed by pico ID
var picoEvents = new eventEmitter();

const BUTTON_OP_PRESS = 3;
const BUTTON_OP_RELEASE = 4;
const BUTTON_FORCE_RELEASE = true;

const LIP_CMD_OUTPUT_REQ = 1;
const LIP_CMD_OUTPUT_SET = 1;
const LIP_CMD_OUTPUT_RAISE = 2;
const LIP_CMD_OUTPUT_LOWER = 3;
const LIP_CMD_OUTPUT_STOP = 4;

function authFileIndexExtension(authIndex,authFileName) {
	function zpad(num, size){ return ('000' + num).substr(-size)};
	return authFileName + '.' + zpad(authIndex,3);
}

function lutronAuthenticate(user,pw,authCallback) {	// callback param=authentication index if ok, undefined
// only one authenticated Lutron bridge is permitted per account
	var authIndex = 0;
	var accessToken;
	var jsonKey;
	var client;
	var appCert;
	var localCert;
	var authenticityToken;
	var cookie;
	var keys;
	var code;
	var haveCerts = false;

	var self = this;

var _Authenticate =  function() {

	fs.stat('appCert', function(err, stats) {
		if (!err) {
			console.log('appCert exists! YEAH!!');
			haveCerts = true;
			authCallback(authIndex);
		} else {
			console.log('No certs will attempt to generate them');
			console.log('Key generation may take a while...');
			forge.pki.rsa.generateKeyPair(2048, function(error, keypair) {
//			   console.log('keys callback');
			   if (error) {
			      console.error('There was an error generating the keys!', error);
			      authCallback();
			      return;
			   };
			   var pem = forge.pki.privateKeyToPem(keypair.privateKey);
			   console.log(pem);
			   fs.writeFileSync("privateKey", pem);
			   keys = keypair;
			   //getCSR();
			   startCodeFetch()
			});

		}
	});
} ();

function startCodeFetch() {

	request.get({
		  headers: {'content-type' : 'application/x-www-form-urlencoded'},
		  followAllRedirects: false,
		  url:     'https:\/\/device-login.lutron.com/users/sign_in',
		}, function(error, response, body){
		  if (error) {
		    console.error('There was an error accessing sign_in!', error);
		    authCallback();
		    return;
		  };
		  var s = body.indexOf('name="authenticity_token" value="');
		  authenticityToken = body.substr(s + 33, 100).split('"')[0].trim();
		  cookie = response.headers['set-cookie'][0].trim();
		  console.log(authenticityToken);
		  callSignIn();
	});
}


function callSignIn() {

	var paramsObject = {utf8: "✓", authenticity_token: authenticityToken, 'user[email]': user, 'user[password]': pw, commit: "Sign In"};
	var params = new URLSearchParams(paramsObject).toString();
	console.log(params);
	request.post({
		headers: {'content-type' : 'application/x-www-form-urlencoded', 'Cookie': cookie},
		url:     'https:\/\/device-login.lutron.com/users/sign_in?' + params,
		body: "",
		}, function(error, response, body) {
			if (error) {
			  console.error('There was an error getting the token!', error);
			  authCallback();
			  return;
			};
			cookie = response.headers['set-cookie'][0].trim();
			console.log(authenticityToken);
			getCode();
	});
}

function getCode() {

	console.log('getCode called');
	request.get({
		headers: {'Cookie' : cookie},
		url:     'https:\/\/device-login.lutron.com/oauth/authorize?redirect_uri=' + encodeURI(REDIRECT_URI) + '&client_id=' + encodeURI(CLIENT_ID) +  '&response_type=code',
		followAllRedirects: true,
		}, function(error, response, body) {
			  if (error) {
			    console.error('There was an error getting the code!', error);
			    authCallback();
			    return;
			  };
			  console.log(authenticityToken);
			  var s = body.indexOf('authorization_code');
			  console.log(s);
			  if (s == -1) {
				console.log('no code, try again');
				console.error('Failed to authorize user ',user);
				authCallback();
			  } else {
				code = body.substr(s + 20, 80).split('<')[0];
				console.log('the code is ' + code);
				//console.log(body);
				cookie = response.headers['set-cookie'][0].trim();
				getCSR();
			  }
	});
}

function getCSR() {

	console.log('in get CSR')
	var csr = forge.pki.createCertificationRequest();

	// fill the required fields
	csr.publicKey = keys.publicKey;

	// use your own attributes here, or supply a csr (check the docs)
	var attrs = [{
	  shortName: 'CN',
	  value: 'Lutron Caseta App'
	}, {
	  shortName: 'C',
	  value: 'US'
	}, {
	  shortName: 'ST',
	  value: 'Pennsylvania'
	}, {
	  shortName: 'L',
	  value: 'Coopersburg'
	}, {
	  shortName: 'O',
	  value: 'Lutron Electronics Co., Inc.'
	}];

	// here we set subject and issuer as the same one
	csr.setSubject(attrs);

	// the actual certificate signing
	csr.sign(keys.privateKey);
	console.log(csr);
	var verified = csr.verify();
	// now convert the Forge certificate to PEM format
	var pem = forge.pki.certificationRequestToPem(csr);
	console.log(pem);

	var strippedPem = pem.replace(/\r/g, "");
	jsonKey = {"remote_signs_app_certificate_signing_request" : strippedPem};
	console.log(JSON.stringify(jsonKey));
	getAccessToken();

	/*
	cmd.get(
		'openssl req -new -key private.pem -out my-csr.pem -subj "/C=US/ST=Pennsylvania/L=Coopersburg/O=Lutron Electronics Co., Inc./CN=Lutron Caseta App"',
		function(err, data, stderr){
			var csr = fs.readFileSync('my-csr.pem', "utf8");
			jsonKey = {"remote_signs_app_certificate_signing_request" : csr};
			console.log(JSON.stringify(jsonKey));
			getAccessToken();
        });
	*/
}

function getAccessToken() {
	var authCallback = cb;

	console.log('in get token');
	console.log('the code is ' + code);
	var paramsObject = {redirect_uri: REDIRECT_URI, 'client_id': CLIENT_ID, client_secret : CLIENT_SECRET, 'code': code, 'grant_type': 'authorization_code'};
	var params = new URLSearchParams(paramsObject).toString();

	request.post({
	  headers: {'content-type' : 'application/x-www-form-urlencoded', 'Cookie' : cookie},
	  url:     'https:\/\/device-login.lutron.com/oauth/token',
	  body:    params, //"code=" + code + "&client_id=e001a4471eb6152b7b3f35e549905fd8589dfcf57eb680b6fb37f20878c28e5a&client_secret=b07fee362538d6df3b129dc3026a72d27e1005a3d1e5839eed5ed18c63a89b27&redirect_uri=https%3A%2F%2Fdevice-login.lutron.com%2Flutron_app_oauth_redirect&grant_type=authorization_code"
	}, function(error, response, body){
	  if (error) {
	    console.error('There was an error obtaining the access token!', error);
	    authCallback();
	    return;
	  };
	  var jsonObject = JSON.parse(body);
	  accessToken = jsonObject.access_token;
	  console.log(accessToken);
	  console.log(body);
	  getCerts();
	});
}

function getCerts() {

	console.log('in get certs');
	request.post({
	  headers: {'content-type' : 'application/json', 'X-DeviceType' : 'Caseta,RA2Select', 'Authorization' : 'Bearer ' + accessToken},
	  url:     'https:\/\/device-login.lutron.com/api/v1/remotepairing/application/user',
	  body:    JSON.stringify(jsonKey)
	}, function(error, response, body){
	  if (error) {
	    console.error('There was an error generating the certificates!', error);
	    authCallback();
	    return;
	  };
	  var jsonObject = JSON.parse(body);
	  appCert = jsonObject.remote_signs_app_certificate;
	  localCert = jsonObject.local_signs_remote_certificate;
	  console.log(appCert);
	  console.log(localCert);
	  fs.writeFileSync("appCert", JSON.stringify(appCert));
	  fs.writeFileSync("localCert", JSON.stringify(localCert));
	  /*
	  fs.writeFileSync("appCert", JSON.stringify(appCert), function(err) {  //SON.stringify(appCert, null, 2)
		if (err) {
          return console.log(err);
		}
	  });
	  fs.writeFile("localCert", JSON.stringify(localCert), function(err) {
		if (err) {
		  return console.log(err);
		}
	  });
	  */
	  haveCerts = true;
	  authCallback(authIndex);
	});
}
}

function parseLip2Leap(lipData, leapData) {
	var lipComplete = [];
	//Make the Devices and Zones objects a single array
	for (var i = 0; i < lipData.Devices.length; i++) {
		lipComplete.push(lipData.Devices[i]);
	}
	if (lipData.Zones) {
		for (var i = 0; i < lipData.Zones.length; i++) {
			lipComplete.push(lipData.Zones[i]);
		}
	}
	var idMismatches = 0;
	//Add the LIP ID to the LEAP data, matching by device name and area, if available
	for (var i in lipComplete) {
		console.log("Matching LIP: ",lipComplete[i].Name);
		for (var j in leapData) {
//			console.log(leapData[j].Name);
			if (lipComplete[i].Name == leapData[j].Name &&
			    (lipComplete[i].Area === undefined ||
			     (leapData[j].FullyQualifiedName.length > 1 &&
			      lipComplete[i].Area.Name == leapData[j].FullyQualifiedName[0]))) {

				console.log("Matched LEAP name to LIP ID: ",lipComplete[i].ID);
				leapData[j]["ID"] = lipComplete[i].ID;
				if (leapData[j]["ID"] != parseInt(leapData[j].href.substring(8))) { // '/device/xxx'
					console.log("Device %s ID mismatch",leapData[j].Name);
					idMismatches++;
				}
			}
		}
//		console.log(leapData);
	}
	//Check if there is a discrepancy between LEAP and LIP ID's and notify the user if there is
	if (idMismatches)
		console.log("%d device ID(s) for LEAP and LIP servers do not match! This might cause problems for you.",idMismatches);
}

function telnetHandler(lcbridgeself, stcallback) {
	var lcBridge = lcbridgeself;
	var lcbridgeix = lcBridge.bridgeix;
	var telnetClient = lcBridge.telnetClient;

	telnetClient.on('data', function(data) {
	  var msgline;
	  var message;

//	  console.log('Telnet #%d received: %s', lcbridgeix, data);
	  // we have to account for GNET> prompts embedded within responses, and multiple-line responses
	  message = data.toString();
	  if (message.indexOf('GNET>') !== -1) {	// a prompt, but it might've been embedded so reprocess line also
	    if (!lcBridge.telnetIsConnect) {	// first prompt upon connection
	      telnetConnectConfirmed();
	    } else { // likely a ping, note that we did get a ping response
	      // currently taking a GNET> prompt as a ping response, but we COULD instead send
	      // ?SYSTEM,10 and get back  ~SYSTEM,12/28/2017,14:40:06  e.g.
	      lcBridge.expectResponse(-1);
	      lcBridge.expectPingback = false;
	      lcBridge.flipPingTag = !lcBridge.flipPingTag;
	      process.stdout.write('Pinged #'+lcbridgeix+' '+(lcBridge.flipPingTag?'T':'t')+'\r');
	    }
	    // now remove the prompt(s) and continue processing the data
	    message = message.replace(/GNET\>\s/g, '');
	  }
	  msgline = message.match(/^.*((\r\n|\n|\r|\s)|$)/gm);	// break up multiple & concatenated lines

	 for (var i = 0, mlcnt = msgline.length; i < mlcnt; i++) {
	  if (msgline[i].length)
		  console.log('Telnet #%d received: %s', lcbridgeix, msgline[i]);
	  if (msgline[i].indexOf('login') !== -1) {
		telnetClient.write('lutron\r\n');
	  } else if (msgline[i].indexOf('password') !== -1) {
		telnetClient.write('integration\r\n');
	  } else if (msgline[i].indexOf('~OUTPUT') !== -1) {	// dimmer/switch level report
		console.log('Device update received');
		if (lcBridge.expectResponse()) {
			lcBridge.expectResponse(-1); // we've received a response
		} else {	// we weren't expecting anything, must be...
			console.log('Looks like a manual/Lutron app change');
		}
		message = msgline[i].split(',');
		var zoneLevel = message[3].split('.')[0];
		var myJSONObject = {bridge: lcBridge.bridgeSN, device: message[1], level: zoneLevel};
		stcallback(myJSONObject);
		return;
	  } else if (msgline[i].indexOf('~DEVICE') !== -1) {	// Pico or scene status update

		message = msgline[i].split(',');
		var picoDevice = message[1];
		var picoButtonCode = message[2];
		var picoButtonOp = message[3];
		var picoButtonForceRelease;
		var buttonconfigix;
		var buttonconfig;

		console.log("Bridge=%d, Device=%d, ButtonCode=%d",lcbridgeix,picoDevice,picoButtonCode);
//		console.log("Button configs:\r\n",picoButtonMethods);
// ??? this bridge indexing isn't good in the long run because the order of bridges might change vs. button methods table
		picoButtonForceRelease = BUTTON_FORCE_RELEASE;
		if (picoDevice == 1) {
			console.log("Virtual button");
			buttonconfig = -1;
		}
		else {
			buttonconfig = picoButtonMethods[lcbridgeix].findIndex(function(i) {
				return (i.device == picoDevice);
			});
			if (buttonconfig >= 0)
				console.log("Use button config[%d]",buttonconfig);
			else
				console.log("No button config");
			//Fix the button mappings & determine whether we can rely on a release message
			switch (picoButtonCode) {
			   case "2":	buttonconfigix = 1;
						break;
			   case "3":	buttonconfigix = 3;
						break;
			   case "4":	buttonconfigix = 2;
						break;
			   case "5":	buttonconfigix = 4;
					picoButtonForceRelease = false;
						break;
			   case "6":	buttonconfigix = 5;
					picoButtonForceRelease = false;
						break;
			   case "8":	buttonconfigix = 1;	// pico PJ2-4B
						break;
			   case "9":	buttonconfigix = 2;	// pico PJ2-4B
						break;
			   case "10":	buttonconfigix = 3;	// pico PJ2-4B
						break;
			   case "11":	buttonconfigix = 4;	// pico PJ2-4B
						break;
			   default: 	buttonconfigix = 0;
						break;
			}
		}
		//console.log(picoButtonMethods[match][button]);
		picoHandler(picoDevice,
		            picoButtonCode,
		            picoButtonForceRelease,
		            (buttonconfig >= 0 && picoButtonMethods[lcbridgeix][buttonconfig][buttonconfigix]), //ramp hold
                            picoButtonOp);
		// console.log("%s active Pico buttons",Object.keys(picoActive).length);

		function picoID(lcbridgeix,picoDevice,picoButtonCode) {
			return lcbridgeix+":"+picoDevice+":"+picoButtonCode;
		}

		// object representing an active Pico (or virtual button for scene)
		function PicoActive(picoBridgeix,picoDevice,picoButtonCode,picoButtonForceRelease) {
			this._picoID = picoID(picoBridgeix,picoDevice,picoButtonCode);
			this._lcbridgeix = picoBridgeix;
			this._picoDevice = picoDevice;
			this._picoButtonCode = picoButtonCode;
			this._picoButtonForceRelease = picoButtonForceRelease;

			this.timerHeld;
			this.timerRelease;
			this.intervalRamp;
			this.wasRamped;

			var startTime;
			this.Init = function () {
				startTime = new Date().getTime();
				this.wasramped = false;
			}
			this.Init ();

			this.elapsed = function () {
				return (startTime)? (new Date().getTime() - startTime) : 0; 
			}
		}
		PicoActive.prototype.quash = function () {
			if (this.timerHeld) {
				clearTimeout(this.timerHeld);
				this.timerHeld = null;
			}
			if (this.timerRelease) {
				clearTimeout(this.timerRelease);
				this.timerRelease = null;
			}
			if (this.intervalRamp) {
				clearInterval(this.intervalRamp);
				this.intervalRamp = null;
			}
			picoEvents.removeAllListeners(this._picoID);
		}
		PicoActive.prototype.restart = function () {
			this.quash();
			this.Init();
		}

		function picoReportJSONObject(picoAction,picoOpName) {
			return {bridge: lutronBridge[picoAction._lcbridgeix].bridgeSN,
                                device: picoAction._picoDevice,
                                button: picoAction._picoButtonCode,
                                action: picoOpName };
		}

		function picoHandler(picoDevice,picoButtonCode,picoButtonForceRelease,picoRampHold,picoButtonOp) {
			var myPicoID = picoID(lcbridgeix,picoDevice,picoButtonCode);

			console.log(picoRampHold?"ramp hold button":"long hold button");

			if (picoButtonOp == BUTTON_OP_PRESS) {  // pressed
			  var curPicoActive;
			  // see if the corresponding button operation object already exists;
			  //     if so, this must be repeated presses without intervening release (re-connect, maybe?)
			  if (picoActive[myPicoID]) {	//reuse the existing object for this pico button
				curPicoActive = picoActive[myPicoID];
				curPicoActive.restart();
			  } else {	// instantiate a new object for this pico button
				picoActive[myPicoID] = new PicoActive(lcbridgeix,picoDevice,picoButtonCode,picoButtonForceRelease);
				curPicoActive = picoActive[myPicoID];
			  }
			  // listen for a release event on this button; note that an event is created per-button
			  picoEvents.on(myPicoID, function(picoNextID,picoButtonNextOp,forcedrelease) {
				if (picoButtonNextOp == BUTTON_OP_RELEASE) {	// released 
				  var nextPicoActive = picoActive[picoNextID];
				  nextPicoActive.quash();
				  var elapsed = nextPicoActive.elapsed();
				  console.log("%s button was %sreleased in %d ms",picoNextID,(forcedrelease)?"force-":"",elapsed);
				  if (!nextPicoActive.wasRamped) {
					var myJSONObject = picoReportJSONObject(nextPicoActive,
                                                               (elapsed < picoShortPressTime)?"pushed":"held");
					stcallback(myJSONObject);
					return;
				  }
				  // kill off this pico button's objects after release (temp & global)
				  nextPicoActive = undefined;
				  delete picoActive[picoNextID];
				} else
				  console.log("unexpected pico event: %s %d",picoNextID,picoButtonNextOp);
			  });
			  if (curPicoActive._picoButtonForceRelease) {
				// if req'dm prepare to force a button release after a specified timeout
				curPicoActive.timerRelease = setTimeout(function() {
					// can't count on a button release message, so simulate one
					picoEvents.emit(this._picoID,this._picoID,BUTTON_OP_RELEASE,true);
				}.bind(curPicoActive), picoHeldTimeout);
			  }
			  if (picoRampHold) {	// ramp hold: start repeating held beyond 'short' press time
				curPicoActive.timerHeld = setTimeout(function() {
					console.log("short-press timeout");
					this.intervalRamp = setInterval(function() {
						this.wasRamped = true;
						console.log("ramp interval")
						var myJSONObject = picoReportJSONObject(this,"held");
						stcallback(myJSONObject);
						return;
					}.bind(this), picoIntervalTime);
				  }.bind(curPicoActive), picoShortPressTime);
			  } // else long hold, just wait for a real (or forced) release
			} else if (picoButtonOp == BUTTON_OP_RELEASE) {	// released
				picoEvents.emit(myPicoID,myPicoID,picoButtonOp,false);
			}
		}
	  }
	 }
	});

	telnetClient.on('error', function errorHandlerTelnet(err) {
		console.log('Pro Bridge # %d telnet comm error %s %s',lcbridgeix,err.code,err);
		if (err.code === 'ETIMEDOUT' || err.code === 'EHOSTUNREACH' || err.code === 'EPIPE') {
			// ... back off and retry connection
			lcBridge.reconnect(true, LCB_RECONNECT_DELAY);
			return;
		}
		else if (err.code === 'ECONNREFUSED' || err.code === 'ECONNRESET') {
			// ... back off and restart connection from scratch
			lcBridge.reconnect(false, 2 * LCB_RECONNECT_DELAY);
			return
		}
		else if (err.code !== undefined) { // likely not an SSL error
			throw(err);
		 	return;
		}
		// geez who knows?? give up
		throw(err);
	});

	telnetClient.on('close', function() {
		lcBridge.telnetIsConnect = false;
		console.log('Disconnected telnet from Pro Bridge #%d',lcbridgeix)
		if (lcBridge.sslClient && !lcBridge.sslClient.destroyed) {
		  // hand the pinging duties back to the SSL connection
		  lcBridge.setPingSSL();
		}
	});

	telnetClient.on('connect', function() {
		console.log('Connected via telnet to Pro Bridge #%d',lcbridgeix);
		// however, we aren't functionally connected until the first GNET> prompt
	});

	telnetClient.connect(23, lcBridge.ip, function() {
	});

	telnetClient.setKeepAlive(true,2000);	// additionally, we'll ping once in a while to ensure re-connect

	function telnetConnectConfirmed () {
		  lcBridge.telnetIsConnect = true;
		  console.log('Telnet #%d Connected!',lcbridgeix)

		  // change the ping scheme to use Telnet instead of SSL for the Pro bridge
		  if (lcBridge.intervalPing)
			clearInterval(lcBridge.intervalPing);
		  lcBridge.expectPingback = false;
		  lcBridge.intervalPing = setInterval(function() {
		    if (lcBridge.telnetIsConnect && !lcBridge.expectPingback && !lcBridge.expectResponse()) {
//		      console.log("Ping #%d",lcbridgeix);
		      process.stdout.write('                        \rPing #'+lcbridgeix+'... ');
		      lcBridge.expectResponse(1);
		      lcBridge.expectPingback = true;
		      telnetClient.write('\r\n');
		      // expected reply:
		      // GNET>
		    }
		    // else     we didn't get a ping response! OR avoid stepping on expected status response w/ping
		    // defer further pings and wait out the socket timeout or other comm error that should ensue
		  }, LCB_PING_INTERVAL);

		  // #ifdef TelnetDebug
		  // Telnet debug console: any line that starts with @ gets sent to Telnet
		  telnetConsoleRL.on('line', (line) => {
		    line = line.trim();
		    if (line.charAt(0) == '@') {
		      line = line.slice(1) + '\r\n';
		      telnetClient.write(line);
		    }
		    // rl.prompt();
		  });
		  // #endif
	}
}

app.post('/connect', function(req,res) {	// ST hub can post here to 'claim' this shim and inform of its IP
	SMARTTHINGS_IP = req.ip;
	res.sendStatus(200);
});

app.post('/status', function(req,res) {
	var lcbridgeix = parseRequestBridgeIX(req.body);
	if (lcbridgeix < 0) {
		res.sendStatus(404);	// we don't know this particular bridge
		return;
	}
	var reqbridge = lutronBridge[lcbridgeix];

  SMARTTHINGS_IP = req.ip;

	var deviceID = req.body.deviceID;
	var deviceZone = req.body.zone;
        console.log('ST status request: Bridge %s, Device %d / Zone %d', lcbridgeix,deviceID,deviceZone);

/* ????? temporary removal for testing zone level requests
	if (reqbridge.telnetIsConnect) {
		// ST SmartApp may only send zone instead of both zone/device ID, for status inquiry, even for Pro bridge
		if (!deviceID) { // if no device ID, get it from the zone 
			var deviceix = reqbridge.leapDevices.findIndex(function(devinfo) {
				return (devinfo.LocalZones && (devinfo.LocalZones[0].href == ('/zone/' + deviceZone)));
			});
			if (deviceix >= 0 && reqbridge.leapDevices[deviceix].ID)
				deviceID = reqbridge.leapDevices[deviceix].ID;
		}
		if (deviceID) {
			reqbridge.telnetClient.write('?OUTPUT,' + deviceID + ',' + LIP_CMD_OUTPUT_REQ + '\r\n');
			reqbridge.expectResponse(1);
			res.sendStatus(202);	// accepted
			return;
		}	// else no device ID can be determined, fall through to use the non-Pro zone scheme
	}
*/
/*
	reqbridge.writeSSL('{"CommuniqueType":"ReadRequest","Header":{"Url":"/zone/' + deviceZone + '/status"}}\n');
	reqbridge.expectResponse(1);
	res.sendStatus(202);	// accepted
*/
	if (deviceZone)
		reqbridge.leapRequestZoneLevel(deviceZone);
	res.sendStatus(202);	// accepted
});

app.get('/devices', function(req, res) {
  SMARTTHINGS_IP = req.ip; 
	console.log("ST device list request");

	var gdbridgeok = [];
	for (var i in lutronBridge) {	// get devices for all known bridges
		lutronBridge[i].writeSSL(communiqueBridgeDevicesRequest);
		lutronBridge[i].expectResponse(1);
		gdbridgeok[i] = false;
	}
	var gdbridgecnt = lutronBridge.length;
	if (!gdbridgecnt) {
		res.sendStatus(404);	// we don't know any bridges
		return;
	}

	lutronBridgeEvents.on(LBE_GOTDEVICES, function lbeReqGotDevices(gdbridgeix) {
		if (!gdbridgeok[gdbridgeix]) {
			gdbridgeok[gdbridgeix] = true;
			gdbridgecnt--;
		}
		if (!gdbridgecnt) {
			var combinedDevicesList = [];
			for (var i in lutronBridge) {	// for all known bridges
				console.log('%s Bridge #%d device data',lutronBridge[i].pro?'Pro':'Std',i);
				combinedDevicesList = combinedDevicesList.concat(lutronBridge[i].leapDevices);
			}
			res.setHeader('Content-Type', 'application/json');
			res.send(combinedDevicesList);

			lutronBridgeEvents.removeListener(LBE_GOTDEVICES, lbeReqGotDevices);
		}
	});
});

app.get('/scenes', function(req, res) {
  SMARTTHINGS_IP = req.ip;
	console.log("ST scenes list request");

	var gsbridgeok = [];
	for (var i in lutronBridge) {	// for all known bridges
		lutronBridge[i].writeSSL(communiqueBridgeScenesRequest);
		lutronBridge[i].expectResponse(1);
		gsbridgeok[i] = false;
	}
	var gsbridgecnt = lutronBridge.length;
	if (!gsbridgecnt) {
		res.sendStatus(404);	// we don't know any bridges
		return;
	}
	lutronBridgeEvents.on(LBE_GOTSCENES, function lbeReqGotScenes(gsbridgeix) {
		if (!gsbridgeok[gsbridgeix]) {
			gsbridgeok[gsbridgeix] = true;
			gsbridgecnt--;
		}
		if (!gsbridgecnt) {
			var combinedScenesList = [];
			for (var i in lutronBridge) {	// for all known bridges
				console.log('Bridge #%d scene data',i);
				combinedScenesList = combinedScenesList.concat(lutronBridge[i].scenesList);
			}
			res.setHeader('Content-Type', 'application/json');
			res.send(combinedScenesList);

			lutronBridgeEvents.removeListener(LBE_GOTSCENES, lbeReqGotScenes);
		}
	});
});

app.post('/scene', function(req, res) {
	var lcbridgeix = parseRequestBridgeIX(req.body);
	if (lcbridgeix < 0) {
		res.sendStatus(404);	// we don't know this particular bridge
		return;
	}
	var reqbridge = lutronBridge[lcbridgeix];

  SMARTTHINGS_IP = req.ip;
	console.log("ST bridge %d scene request %j",lcbridgeix,req.body);

	if (reqbridge.telnetIsConnect) {
		reqbridge.telnetClient.write('#DEVICE,1,' + req.body.virtualButton + ',' + BUTTON_OP_PRESS + '\r\n');
		reqbridge.telnetClient.write('#DEVICE,1,' + req.body.virtualButton + ',' + BUTTON_OP_RELEASE + '\r\n');
		reqbridge.expectResponse(2);
	} else {
		reqbridge.writeSSL('{"CommuniqueType": "CreateRequest","Header": {"Url":"/virtualbutton/' + req.body.virtualButton + '/commandprocessor"},"Body": {"Command": {"CommandType": "PressAndRelease"}}}\n');
		reqbridge.expectResponse(1);
	}
	res.sendStatus(202);	// accepted
// btw 'real' Pico buttons can be triggered remotely in a similar way, with 'real' button numbers for telnet, or maybe...
// e.g. {"CommuniqueType":"CreateRequest","Header":{"Url":"/button/122/commandprocessor"},"Body":{"Command":{"CommandType":"PressAndHold"}}}
});

app.post('/setLevel', function(req, res) {
	var lcbridgeix = parseRequestBridgeIX(req.body);
	if (lcbridgeix < 0) {
		res.sendStatus(404);	// we don't know this particular bridge
		return;
	}
	var reqbridge = lutronBridge[lcbridgeix];
  SMARTTHINGS_IP = req.ip;
	console.log("ST bridge %d set level request %j",lcbridgeix,req.body);

// ??? ST SmartApp can really just send device ID, as we can look up the zone locally if needed
	if (reqbridge.telnetIsConnect && req.body.deviceID != null) {
		reqbridge.telnetClient.write('#OUTPUT,' + req.body.deviceID + ',' + LIP_CMD_OUTPUT_SET + ',' + req.body.level + ' \r\n');
		reqbridge.expectResponse(1);
	} else {
		reqbridge.writeSSL('{"CommuniqueType":"CreateRequest","Header":{"Url":"/zone/' + req.body.zone + '/commandprocessor"},"Body":{"Command":{"CommandType":"GoToLevel","Parameter":[{"Type":"Level","Value":' + req.body.level +'}]}}}\n');
		reqbridge.expectResponse(1);
	}
	res.sendStatus(202);	// accepted
});

app.post('/on', function(req, res) {
	var lcbridgeix = parseRequestBridgeIX(req.body);
	if (lcbridgeix < 0) {
		res.sendStatus(404);	// we don't know this particular bridge
		return;
	}
	var reqbridge = lutronBridge[lcbridgeix];
  SMARTTHINGS_IP = req.ip;
	console.log("ST bridge %d on request %j",lcbridgeix,req.body);

// ??? ST SmartApp can really just send device ID, as we can look up the zone locally if needed
	if (reqbridge.telnetIsConnect && req.body.deviceID != null) {
		reqbridge.telnetClient.write('#OUTPUT,' + req.body.deviceID + ',' + LIP_CMD_OUTPUT_SET + ',' + '100' + ' \r\n');
		reqbridge.expectResponse(1);
	} else {
		reqbridge.writeSSL('{"CommuniqueType":"CreateRequest","Header":{"Url":"/zone/' + req.body.zone + '/commandprocessor"},"Body":{"Command":{"CommandType":"GoToLevel","Parameter":[{"Type":"Level","Value":' + '100' +'}]}}}\n');
		reqbridge.expectResponse(1);
	}
	res.sendStatus(202);	// accepted
});

app.use(function(err, req, res, next){ // make sure this is the last express app.
  console.error(err);
  res.sendStatus(500);
});

process.on('uncaughtException', function (err) {
  console.log('Caught exception: ',err.code);
//  var stack = new Error().stack;
//  console.log( stack );
  throw(err);
});

process.on('exit', function(code) {
  for (var i in lutronBridge) {
	lutronBridge[i].disconnect();
  }
  console.log('\r\nExiting with code:', code);
});

process.on('SIGINT', function () {
  //graceful shutdown on Ctrl+C
  process.exit(2);
});

function parseRequestBridgeIX(reqbody) {
  if (reqbody.bridgeSN === undefined)
    return 0;	// compatibility default bridge=0
  else {
    if (!(reqbody.bridgeSN in lutronBridgeSN))
      return -1;	// a specific bridge was requested but we don't know it (yet?)
    else
      return lutronBridgeSN[reqbody.bridgeSN];
  }
}

function sendSmartThingsJSON(jsonData) {	// common fn to send to ST
  if (ipaddr.isValid(SMARTTHINGS_IP)) {
    var stip4 = ipaddr.process(SMARTTHINGS_IP).toString();	// ensure we don't have some weird IPv6-ifized IPv4
    console.log('sending to ST @ %s',stip4);

    request({
	url: 'http:\/\/' + stip4 + ':' + STLAN_PORT,
	method: "POST",
	json: true,	// self-stringifies body object to JSON
	body: jsonData
    }, function (error, response, body){
	if (error)
	  throw(error);	// ??? this could use a little more finesse!
       }); 
  } else console.log('ST not connected yet!');
}

// object representing Lutron Caseta bridge
function lcSmartBridge(lcbridgeix, lcbridgeip) {
	this.bridgeix = lcbridgeix;
	this.ip = lcbridgeip;
	this.macaddr = null;
	this.bridgeSN = "";
	this.pro = false;
	this.sslClient = null;
	this.telnetClient = null;
	this.telnetIsConnect = false;
	this.leapDevices = null;
	this.lipDevices = null;
	this.scenesList = null;
	this.expectedResponseCnt = 0;
	this.timerResponse;
	this.timerBackoff;
	this.expectPingback = false;
	this.flipPingTag = false;
	this.intervalPing;
	var self = this;	// this lc bridge

	// track the minimum number of bridge responses expected and try to reconnect on failure
	// parameter: expectedresponseinc:
	//		not passed/undefined = return pending minimum response count
	//		false/0 = reset and disable expected response monitor
	//		+/-N = add or subtract N from pending minimum response count
	this.expectResponse = function (expectedresponseincr) {
		if (expectedresponseincr !== undefined) {
			if (expectedresponseincr && expectedresponseincr > 0) {
				self.expectedResponseCnt += Math.trunc(expectedresponseincr);
				self.timerResponse = setTimeout(function lcbResponseTimeout() {
					console.log('Lutron SmartBridge #%d isn\'t responding',self.bridgeix);
					self.reconnect(true,500);
				}, LCB_RESPONSE_TIMEOUT);
			}
			else {
				if (!expectedresponseincr)	// unconditional disable & reset of response timeout
					self.expectedResponseCnt = 0;
				else
					self.expectedResponseCnt += Math.trunc(expectedresponseincr);
				if (self.expectedResponseCnt <= 0) {
					self.expectedResponseCnt = 0;
					if (self.timerResponse != null)
						clearTimeout(self.timerResponse);
				}
			}
		}
		return self.expectedResponseCnt;
	}

	this.initialize = function(err, lcbinitcallback) {
// ??? temporary macaddr handling
if (!!sb_mac[0])
	this.macaddr = sb_mac[0];
	    connectSSL(false, function lcbGetInitialBridgeConfig(resumed) {
// ??? maybe we want to set a timeout and return err if these initial requests are not filled
		// request and await the initial devices list
		console.log('Bridge #%d initial devices request',self.bridgeix);
		lutronBridgeEvents.on(LBE_GOTDEVICES, function lbeInitGotDevices(gdbridgeix) {
			if (gdbridgeix != self.bridgeix)
				return;	// not this bridge, let another bridge's listener have it
			lutronBridgeEvents.removeListener(LBE_GOTDEVICES, lbeInitGotDevices);

			if (self.pro)	// wait until initial device list acquired before starting the Pro Bridge telnet client
			    initTelnet();

			// request and await the initial scenes list
			console.log('Bridge #%d initial scenes request',self.bridgeix);
			lutronBridgeEvents.on(LBE_GOTSCENES, function lbeInitGotScenes(gsbridgeix) {
				if (gsbridgeix != self.bridgeix)
					return;	// not this bridge, let another bridge's listener have it
				lutronBridgeEvents.removeListener(LBE_GOTSCENES, lbeInitGotScenes);

// ??? do we really want to force this update to SmartThings, or expect it to ask first? Maybe only if we know we're connected?
				// roll through the device list and send level for anything marked with a zone # to SmartThings hub
				console.log('Bridge #%d initial levels update request',self.bridgeix);
				self.leapDevices.filter(function(brdev){return 'LocalZones' in brdev})
					   	.forEach(function(brdev) {
							for (var i in brdev.LocalZones) {
								var devzone = brdev.LocalZones[i].href.replace( /\/zone\//i, '');
								if (devzone)
									self.leapRequestZoneLevel(devzone);
							}
						});

				if (typeof lcbinitcallback === "function") {
					lcbinitcallback();
					return;
				}
			});
			self.writeSSL(communiqueBridgeScenesRequest);
			self.expectResponse(1);
		});
		self.writeSSL(communiqueBridgeDevicesRequest);
		self.expectResponse(1);
	    });
	}

	this.writeSSL = function(data,encoding,cb) {
	    if (self.sslClient.destroyed) {
		connectSSL(true, function lcbResumeSessionOnWrite(resumed) {
		    self.sslClient.write(data);
		});
	    } else self.sslClient.write(data);
	    if (typeof cb === "function")
		cb();
	}

	function connectSSL(resume,cbonconnect) {
	    var options = {};
	    var authIndex = 0;

	    self.expectResponse(false);	// disable expected response monitor
	    if (resume) { // resume half-closed session
		options = {
		   session: self.sslSession,
   		   rejectUnauthorized: false
	        };
	    } else { // new session -- we may need to try multiple certs/keys until we hit the right one for this bridge
		options = {
		   key:  fs.readFileSync('privateKey'), //key  : fs.readFileSync('private.pem'),
		   cert : JSON.parse(fs.readFileSync('appCert')), //remote_signs_app_certificate
		   ca: JSON.parse(fs.readFileSync('localCert')),  //local_signs_remote_certificate
		   rejectUnauthorized: false,
	//	   allowHalfOpen: true,	// allow other end to FIN w/o closing socket for writes
		};
	    }
	    self.sslClient = tls.connect(8081, self.ip, options, function lcbConnected () {
		console.log("Lutron SmartBridge #%d SSL %sconnected at " + Date.now(),self.bridgeix,(resume)? "re-":"");
		self.sslClient.on('end', function() {
		  console.log("Lutron SmartBridge #%d disconnected itself",self.bridgeix)
		  // session is resumable if no error, so let it go for now
		});
		self.sslClient.on('close', function(erred) {
		  console.log("Lutron SmartBridge #%d comm closed %s",self.bridgeix,(erred)? "with error":"normally")
		  // session is resumable if no error, so let it go for now
		});

		if (!resume) {	// just turning on keep-alive didn't forstall half-disconnects, so... resume instead
		  self.sslSession = Buffer.from(self.sslClient.getSession());	// save this for resumes afte FIN
		  fs.writeFile(authFileWIndexExt(authIndex,"CertMAC"),JSON.stringify(self.macaddr));
		}
		listenSSL(handleIncomingSSLData);
		if (!self.telnetIsConnect)
		  self.setPingSSL();
		if (typeof cbonconnect === "function")
		    cbonconnect(resume);
	    });
	    setErrorHandlerSSL();
	}

	this.reconnect = function (attemptresume,backoffms) {
	    if (self.sslClient !== null && !self.sslClient.destroyed) {
		self.sslClient.destroy();
	    }
	    self.expectResponse(false);
	    // kill the current pinger
	    self.expectPingback = false;
	    clearInterval(self.intervalPing);
	    // wait a bit before trying to reconnect to the bridge
	    self.timerBackoff = setTimeout(function() {
		console.log("Lutron SmartBridge #%d reconnecting...",self.bridgeix);
		connectSSL(attemptresume && (self.sslSession != null), function lcbReconnected(resumed) {
		    if (!resumed || (self.telnetClient !== null && !self.telnetClient.destroyed)) {
			self.telnetIsConnect = false;
			self.telnetClient.destroy();
			self.telnetClient = null;
		    }
		    if (self.pro)
			initTelnet();
		});
	    }, backoffms);
	}

	this.disconnect = function() {
		if (self.telnetIsConnect) {
			self.telnetIsConnect = false;
			self.telnetClient.end('LOGOUT\r\n');
			self.telnetClient = null;
		}
		if (self.sslClient && !self.sslClient.destroyed) {
			self.sslClient.destroy();
		};
	}

	function handleIncomingSSLData(data) {
		var jsonData = JSON.parse(data.toString());

		if (jsonData.Header.MessageBodyType == 'OnePingResponse') {
		  self.expectResponse(-1);
                  self.expectPingback = false;
		  self.flipPingTag = !lcBridge.flipPingTag;
		  process.stdout.write('Pinged #'+self.bridgeix+' '+(self.flipPingTag?'S':'s')+'\r');
		  return;
		}
		console.log('Incoming SSL is proper JSON');
		console.log(data);	// moved here from SSL listener

		if (jsonData.Header.MessageBodyType == 'OneLIPIdListDefinition') {
		  console.log('LIP Data was received and sent to parser');
		  self.expectResponse(-1);

		  self.lipDevices = jsonData.Body.LIPIdList;

		  // update LEAP data w/ LIP IDs in-place
		  parseLip2Leap(self.lipDevices, self.leapDevices);
		  console.log('The merged LEAP Data is: %o\n',self.leapDevices)
		  lutronBridgeEvents.emit(LBE_GOTDEVICES,self.bridgeix);
		} else if (jsonData.Header.MessageBodyType == 'MultipleDeviceDefinition') {
		  console.log('LEAP Data was received and sent to parser');
		  self.expectResponse(-1);

		  self.leapDevices = jsonData.Body.Devices;

		  // identify the bridge itself
		  self.bridgeSN = self.leapDevices[0].SerialNumber;
		  lutronBridgeSN[self.bridgeSN] = self.bridgeix;	// build the reverse lookup SN:index table

		  // attach an initial ID to each device based on its /device/ii property (pro bridge LIP data may update it)
		  // attach bridge SN to each device so we can tell them apart in requests
		  for (var j in self.leapDevices) {
                        try {
                            self.leapDevices[j].ID = Number(self.leapDevices[j].href.replace( /\/device\//i, ''));
                        } catch (e) { }
			self.leapDevices[j].Bridge = self.bridgeSN;
		  }

// DEBUGGERY
if (overrideNoPro) {
	// pretend Pro bridge is Std, no Telnet
	console.log('TEST Std Bridge');
	lutronBridgeEvents.emit(LBE_GOTDEVICES,self.bridgeix);
} else {
		  if (self.leapDevices[0].ModelNumber.indexOf('PRO') != -1) {
		    self.pro = true;
		    console.log('Pro Bridge');
		    // request the LIP device data, only available on the Pro hub
		    self.writeSSL(communiqueBridgeLIPDevicesRequest);
		    self.expectResponse(1);
		  }
		  else {
		    console.log('Std Bridge');
		    lutronBridgeEvents.emit(LBE_GOTDEVICES,self.bridgeix);
		 }
}
		} else if (jsonData.Header.MessageBodyType == 'MultipleVirtualButtonDefinition') {
		  console.log('Scene Data Received');
		  self.expectResponse(-1);
		  var buttons = jsonData.Body.VirtualButtons;
		  var tempList = [];
		  for (var i = 0; i < buttons.length; i++) {
		    if (buttons[i].IsProgrammed == true) {
			tempList[tempList.push(buttons[i])-1].Bridge = self.bridgeSN;
		    }
		  }
		  self.scenesList = tempList;
		  console.log(tempList);
		  lutronBridgeEvents.emit(LBE_GOTSCENES,self.bridgeix);
		} else { // some other response; just pass it along to Smartthings hub (redundant if PRO telnet)
		  console.log("SSL data from %s Bridge %s",(self.pro)?"Pro":"Std",(self.telnetIsConnect)?"ignored":"sent to ST hub");
		  if (!self.telnetIsConnect) {
		    self.expectResponse(-1);

		    // if it's a zone status update, translate to what the SmartApp understands
		    // currently the SmartApp has a bug that skips LEAP-style status update messages :-(
		    // ... so we'll use the 'Telnet' version instead for now
		    if (jsonData.Header.MessageBodyType == 'OneZoneStatus' &&
			jsonData.Header.StatusCode == '200 OK') {
			var rzfld = jsonData.Header.Url.split('\/');
			if (rzfld[0] == '' && rzfld[1] == 'zone' && rzfld[3] == 'status') {
			    // determine the device ID from the zone's first matching device
			    var dlevel = jsonData.Body.ZoneStatus.Level;
			    var dix = self.leapDevices.findIndex(function(tdev) {
				return (tdev.LocalZones &&
				        jsonData.Body.ZoneStatus.Zone &&
				        (tdev.LocalZones[0].href == jsonData.Body.ZoneStatus.Zone.href));
			    });
			    if (dix > 0 && self.leapDevices[dix].ID) {
				jsonData = {bridge: self.bridgeSN, device: self.leapDevices[dix].ID, level: dlevel};
			    }       // else no device with a matching zone, just fall through
			}
		    } // otherwise just send it along as-is and let the SmartApp deal with it!
		    sendSmartThingsJSON(jsonData);
		  }
		}
	}

	function listenSSL(msgcallback) {
		var bufferedData = '';

		self.sslClient.on('data', function (data) {
//			console.log('data in listenSSL');
			bufferedData += data;
			try {
			  JSON.parse(bufferedData.toString());
//			  console.log("Buffered data is proper json");
			  var fullmessage = bufferedData;
//			  console.log(fullmessage);
			  bufferedData = '';
			  msgcallback(fullmessage);
			  return;
			} catch (e) {
			  console.log('json not valid, probably don\'t have it all yet');
//			  console.log(e);
			}
		});
	}

	this.setPingSSL = function() {
		// send an occasional ping to ensure we're still connected to the bridge
		// if a telnet connection is made to a Pro bridge, that will assume ping handling
		if (self.intervalPing)
			clearInterval(self.intervalPing);
		self.expectPingback = false;
		self.intervalPing = setInterval(function() {
		  if (!self.expectPingback && !self.expectResponse()) {
		    process.stdout.write('                        \rPing #'+lcbridgeix+'... ');
//		    console.log("Ping #%d",self.bridgeix);
		    self.expectResponse(1);
		    self.expectPingback = true;
		    self.writeSSL(communiqueBridgePingRequest);
		    // expected reply:
		    // {"CommuniqueType":"ReadResponse","Header":{"MessageBodyType":"OnePingResponse","StatusCode":"200 OK","Url":"/server/status/ping"},"Body":{"PingResponse":{"LEAPVersion":1.106}}}
		  }
		  // else     we didn't get a ping response! OR avoid stepping on expected status response w/ping
		    // defer further pings and wait out the socket timeout or other comm error that should ensue
		}, LCB_PING_INTERVAL);
	}

	function setErrorHandlerSSL() {
		self.sslClient.on('error', function errorHandlerSSL(err) {
			console.log('Lutron SmartBridge #%d SSL comm error %s %s',self.bridgeix,err.code,err);
			if (err.code === 'ETIMEDOUT' || err.code === 'EHOSTUNREACH') {
			    // ... back off and retry connection
			    self.reconnect(true, LCB_RECONNECT_DELAY);
			}
			else if ( err.code === 'ECONNREFUSED' || err.code === 'ECONNRESET') {
				// ... back off and restart connection from scratch
				self.reconnect(false, 2 * LCB_RECONNECT_DELAY)
			}
			else if (err.code !== undefined) { // likely not an SSL error, give up
			    throw(err);
			    return;
			} else { // likely an SSL error following an ECONNRESET
// ??? if it's a bad certificate, not much we can do until we have multi-cert handler
			    if (err.message.indexOf('bad certificate') != -1 ||
				err.message.indexOf('SSL alert number 42') != -1) {
				console.log('Wrong Certificate for this bridge!',self.macaddr);
				throw(err);
				return;
			    }
// ???? otherwise let it go for now, maybe it's ok
			}
		});
	}

	function initTelnet() {
	    if (!self.telnetIsConnect) {
		console.log('starting telnet connection')
		self.telnetIsConnect = false;
		if (self.telnetClient !== null && !self.telnetClient.destroyed)
			self.telnetClient.destroy();
		self.telnetClient = new net.Socket();
		telnetHandler(self, sendSmartThingsJSON);
	    }
	}
}
lcSmartBridge.prototype.leapRequestZoneLevel = function (deviceZone) {
	this.writeSSL('{"CommuniqueType":"ReadRequest","Header":{"Url":"/zone/' + deviceZone + '/status"}}\n');
	this.expectResponse(1);
}

function ssdpConnectLocation() {
	return 'http:\/\/' + ip.address() + ':' + stReqPort + (SMARTTHINGS_IP ? '/status' : '/connect');
}

exports.startup = function(SB_IP, ST_IP, lcbUser, lcbPassword, bMethods, spTime, intTime) {
	// the Lutron account user/pw probably need to be spec'd per-bridge, as only one bridge per account
	var user = lcbUser;
	var pw = lcbPassword;


// DEBUGGERY
// ??? generalize this argument detector for position tolerance!
	overrideNoPro = (process.argv.length > 2 && process.argv[2].toUpperCase() == 'NOPRO');

	picoShortPressTime = spTime;
	picoIntervalTime = intTime;

	lutronAuthenticate(user, pw, function (authIndex) { 
		assert(authIndex !== undefined); // bail out if we can't get the account certificate

		// find one or more Lutron bridges, and continue monitoring for changes
var bjDelayTimer = setTimeout(function () {
console.log('RE-finding the Lutron SmartBridge (test bonjour)');
var mdnsLutronBridge = mDNSHandler.find({ type: 'lutron' },
					function sniffLutronBridges(lutronService,isupdate) {

// we really want a notification when any of this changes, too
    console.log('Lutron SmartBridge mDNS %s / now %d services',(isupdate)?'updated':'found',mdnsLutronBridge.services.length);
    console.log('Lutron SmartBridge mDNS Name: ' + lutronService.name);
    console.log('Lutron SmartBridge mDNS FQDN: ' + lutronService.fqdn);
    console.log('Lutron SmartBridge mDNS IP: ' + lutronService.addresses[0]);
    console.log('Lutron SmartBridge mDNS Host: ' + lutronService.host);
    console.log('Lutron SmartBridge mDNS MAC: ' + lutronService.txt.macaddr);
    console.log('Lutron SmartBridge mDNS TTL (sec): ' + lutronService.ttl);

// only usable bridge if
// mdnsLutronBridge.service[0].txt.fw_status == 'Noupdate'
// mdnsLutronBridge.service[0].txt.nw_status == '11:InternetWorking'
// mdnsLutronBridge.service[0].txt.st_status == 'good'
// else flush, fall back and retry in a while

    if (!lutronBridge[0] ||  lutronBridge[0].macaddr == lutronService.txt.macaddr) {
	    SB_IP[0] = mdnsLutronBridge.services[0].addresses[0]; //should check if ipv4 !
	    sb_mac[0] = lutronService.txt.macaddr;
    }

if (!isupdate && !lutronBridge[0]) {

		for (var i = 0; i < SB_IP.length; i++) {
			console.log('Lutron Bridge: %s',SB_IP[i]);
			lutronBridge.push(new lcSmartBridge(i, SB_IP[i]));
			lutronBridge[i].initialize();

// ??? the button methods probably need to be spec'd per-bridge, but in the meantime...
			picoButtonMethods[i] = [];
			if (bMethods) {
				if (bMethods[0].constructor === Array) {
					if (bMethods.length > i)
						picoButtonMethods[i] = bMethods[i];
				}
				else
					picoButtonMethods[i] = bMethods;
			}
		}
}
});
},1000);	// only delaying during this test else no answer sometimes
		SMARTTHINGS_IP = ST_IP;

		// find a localhost port we can use to receive ST requests, then advertise for ST connection
		getport(DEFAULT_REQST_PORT, function (err,p) {
			if (err) throw (err);

			stReqPort = p;
	                stReqServer = app.listen(stReqPort);
	                console.log('Listening for SmartThings requests on port %d...',stReqPort);

			//SSDP server for Service Discovery
			ssdp = new ssdpServer({
				sourcePort: 1900,
			        udn: 'uuid:' + uuidv1(),
		        	adInterval: 60000,
				suppressRootDeviceAdvertisements: true,
			//	location: 'http:\/\/' + ip.address() + ':' + DEFAULT_REQST_PORT + '/status',
				location: ssdpConnectLocation,
			});

			ssdp.addUSN('urn:schemas-upnp-org:device:RPi_Lutron_Caseta:1');

//			ssdp.on('advertise-alive', function (headers) { });

//			ssdp.on('advertise-bye', function (headers) { });

			process.on('exit', function(){
				ssdp.stop() // advertise shutting down and stop listening 
				stReqServer.close();
			})

			ssdp.start(); // start the SSDP advertisment once we're listening
		});
	});
};
