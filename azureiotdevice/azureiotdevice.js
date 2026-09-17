
// Copyright (c) Eric van Uum. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/**
 * The "azure-iot-device" node enables you to represent an Azure IoT Device in Node-Red.
 * The node provide connecting a device using connection string and DPS
 * You can use a full connection string, a SAS key and a X.509 attestation
 *
 * The device node enables D2C, C2D messages, Direct Methods, Desired and Reported properties.
 * You can connect to IoT Edge as a downstream device, IoT Hub and IoT Central.
 */
module.exports = function (RED) {
    'use strict'
    const Client = require('azure-iot-device').Client;
    const Message = require('azure-iot-device').Message;

    // Only AMQP(WS) or MQTT(WS) used as protocol, no HTTP support
    const Protocols = {
        amqp: require('azure-iot-device-amqp').Amqp,
        amqpWs: require('azure-iot-device-amqp').AmqpWs,
        mqtt: require('azure-iot-device-mqtt').Mqtt,
        mqttWs: require('azure-iot-device-mqtt').MqttWs
    };

    // Only AMQP(WS) or MQTT(WS) used as protocol, no HTTP support
    const ProvisioningProtocols = {
        amqp: require('azure-iot-provisioning-device-amqp').Amqp,
        amqpWs: require('azure-iot-provisioning-device-amqp').AmqpWs,
        mqtt: require('azure-iot-provisioning-device-mqtt').Mqtt,
        mqttWs: require('azure-iot-provisioning-device-mqtt').MqttWs
    };

    const SecurityClient = {
        x509: require('azure-iot-security-x509').X509Security,
        sas: require('azure-iot-security-symmetric-key').SymmetricKeySecurityClient
    };

    const ProvisioningDeviceClient = require('azure-iot-provisioning-device').ProvisioningDeviceClient;
    const GlobalProvisoningEndpoint = "global.azure-devices-provisioning.net";

    const crypto = require('crypto');
    const forge = require('node-forge');
    var pki = forge.pki;

    // Hard limits. Everything reaching this node over a flow wire, over the
    // network (C2D, desired properties, DPS responses) or out of an imported
    // flow file is untrusted, so every unbounded structure gets a ceiling.
    const MAX_PAYLOAD_DEPTH = 20;                 // guards against stack exhaustion
    const MAX_PENDING_METHOD_RESPONSES = 100;     // guards against unbounded array growth
    const METHOD_RESPONSE_TTL = 150000;           // ms before an orphaned response is evicted
    const MAX_RETRY_INTERVAL = 300000;            // ms ceiling for the reconnect backoff
    const MAX_HOSTNAME_LENGTH = 253;
    const MAX_DEVICEID_LENGTH = 128;
    const MAX_SASKEY_LENGTH = 1024;

    // A connection string is a ";"-separated list of "key=value" pairs. Any value
    // concatenated into it must therefore be unable to contain a ";", otherwise it
    // can inject or override other connection string properties (a device id of
    // "dev;GatewayHostName=attacker.example" redirects the device, and the
    // credentials it presents, to a host of the attacker's choosing).
    const HOSTNAME_PATTERN = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
    const DEVICEID_PATTERN = /^[^;\s\x00-\x1f\x7f]+$/;
    const SASKEY_PATTERN = /^[A-Za-z0-9+/=_-]+$/;
    const SCOPEID_PATTERN = /^[^;\s\x00-\x1f\x7f]+$/;

    // Keys that must never be copied out of untrusted JSON into an object we
    // build, to avoid polluting Object.prototype further down the SDK.
    const FORBIDDEN_KEYS = ['__proto__', 'constructor', 'prototype'];

    // Credential material that must not end up in logs, node status or the error
    // output of the node. SDK errors regularly quote the connection string.
    const SECRET_PATTERN = /((?:SharedAccessKey|SharedAccessSignature|sig|se|skn|passphrase|password)\s*=\s*)([^;&"'\s]+)/gi;
    const PEM_PATTERN = /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g;

    const statusEnum = {
        connected: { fill: "green", shape:"dot", text: "Connected" },
        connecting: { fill: "blue", shape:"dot", text: "Connecting" },
        provisioning: { fill: "blue", shape:"dot", text: "Provisioning" },
        disconnected: { fill: "red", shape:"dot", text: "Disconnected" },
        error: { fill: "grey", shape:"dot", text: "Error" }
    };

    // Setup node-red node to represent Azure IoT Device
    function AzureIoTDevice(config) {
        // Create the Node-RED node
        RED.nodes.createNode(this, config);

        const node = this;

        // Set properties
        node.deviceid = config.deviceid;
        node.pnpModelid = config.pnpModelid;
        node.connectiontype = config.connectiontype;
        node.authenticationmethod = config.authenticationmethod;
        node.enrollmenttype = config.enrollmenttype;
        node.iothub = config.iothub;
        node.isIotcentral = config.isIotcentral;
        node.scopeid = config.scopeid;
        node.saskey = config.saskey;
        node.protocol = config.protocol;
        node.retryInterval = config.retryInterval;
        node.methods = config.methods;
        node.DPSpayload = config.DPSpayload;
        node.gatewayHostname = config.gatewayHostname;
        node.cert = config.cert;
        node.key = config.key;
        node.passphrase = config.passphrase;
        node.ca = config.ca;
        // Array to hold the direct method responses
        node.methodResponses = [];
        //** @type {device.Client} */ this.client;
        node.client = null;
        //** @type {device.Twin} */ this.twin;
        node.twin = null;
        // Connection lifecycle state
        node.closing = false;
        node.starting = false;
        node.connectAttempts = 0;
        node.retryTimer = null;

        // The input and close handlers are registered exactly once, here. They must
        // not be registered from the (re)connect path: a node that reconnected N
        // times would otherwise hold N input listeners, send every incoming message
        // N times, and leak listeners until the process died.
        node.on('close', function (done) {
            node.closing = true;
            cancelRetry(node);
            closeAll(node);
            done();
        });

        // Listen to node input to send telemetry or reported properties
        node.on('input', function (msg, send, done) {
            done = done || function (err) { if (err) { node.error(err, msg); } };
            handleInput(node, msg, done);
        });

        setStatus(node, statusEnum.disconnected);

        // Initiate
        startDevice(node);
    };

    // Set status of node on node-red
    var setStatus = function (node, status) {
        node.status({ fill: status.fill, shape: status.shape, text: status.text });
    };

    // Strip credential material out of anything that is logged or emitted.
    function redactText(text) {
        if (typeof text !== 'string') {
            return text;
        }
        return text.replace(SECRET_PATTERN, '$1***REDACTED***')
                   .replace(PEM_PATTERN, '-----BEGIN PRIVATE KEY----- ***REDACTED*** -----END PRIVATE KEY-----');
    }

    // Redact a value of any shape while keeping its structure intact where possible.
    function redactValue(value) {
        if (value instanceof Error) {
            return { name: value.name, message: redactText(value.message) };
        }
        if (typeof value === 'string') {
            return redactText(value);
        }
        try {
            var serialized = JSON.stringify(value);
            if (serialized === undefined) {
                return redactText(String(value));
            }
            return JSON.parse(redactText(serialized));
        } catch (err) {
            return redactText(String(value));
        }
    }

    // Safe stringify for log lines: never throws, never leaks secrets.
    function safeStringify(value) {
        try {
            var serialized = JSON.stringify(value);
            return redactText(serialized === undefined ? String(value) : serialized);
        } catch (err) {
            return '[unserializable value]';
        }
    }

    // Send catchable error to node-red
    var error = function (node, payload, message) {
        var msg = {};
        msg.topic = 'error';
        msg.message = redactText(message);
        msg.payload = redactValue(payload);
        node.error(msg);
    }

    // Validate a value that is concatenated into an Azure connection string.
    function validateConnectionStringValue(label, value, pattern, maxLength) {
        if (typeof value !== 'string' || value.length === 0) {
            throw new Error(label + ' is missing or not a string.');
        }
        if (value.length > maxLength) {
            throw new Error(label + ' exceeds the maximum length of ' + maxLength + ' characters.');
        }
        if (!pattern.test(value)) {
            throw new Error(label + ' contains characters that are not allowed.');
        }
        return value;
    }

    // Recursively copy untrusted JSON, dropping prototype-polluting keys and
    // refusing structures nested deep enough to blow the stack.
    function sanitizePayload(value, depth) {
        depth = depth || 0;
        if (depth > MAX_PAYLOAD_DEPTH) {
            throw new Error('Payload is nested deeper than the allowed ' + MAX_PAYLOAD_DEPTH + ' levels.');
        }
        if (Array.isArray(value)) {
            var list = [];
            for (var i = 0; i < value.length; i++) {
                list.push(sanitizePayload(value[i], depth + 1));
            }
            return list;
        }
        if (value !== null && typeof value === 'object') {
            var clean = {};
            var keys = Object.keys(value);
            for (var k = 0; k < keys.length; k++) {
                if (FORBIDDEN_KEYS.indexOf(keys[k]) !== -1) {
                    continue;
                }
                clean[keys[k]] = sanitizePayload(value[keys[k]], depth + 1);
            }
            return clean;
        }
        return value;
    }

    // Parse untrusted JSON. Throws on malformed input; callers must handle it.
    function parseJson(text) {
        return sanitizePayload(JSON.parse(text), 0);
    }

    // Check if valid PEM cert
    function verifyCertificatePem(node, pem) {
        try {
            // Get the certificate from pem, if successful it is a cert
            node.log(node.deviceid + ' -> Verifying PEM Certificate');
            var cert = pki.certificateFromPem(pem);
        } catch (err) {
            return false;
        }
        return true;
    };

    // Compute device SAS key
    function computeDerivedSymmetricKey(masterKey, regId) {
        return crypto.createHmac('SHA256', Buffer.from(masterKey, 'base64'))
            .update(regId, 'utf8')
            .digest('base64');
    };

    // Drop method responses that will never be claimed, so a flow answering
    // commands that already timed out (or that were never asked) cannot grow this
    // array without bound.
    function pruneMethodResponses(node) {
        var now = Date.now();
        node.methodResponses = node.methodResponses.filter(function (entry) {
            return (now - entry.timestamp) < METHOD_RESPONSE_TTL;
        });
        while (node.methodResponses.length > MAX_PENDING_METHOD_RESPONSES) {
            node.methodResponses.shift();
        }
    };

    // Cancel a pending reconnect attempt.
    function cancelRetry(node) {
        if (node.retryTimer) {
            clearTimeout(node.retryTimer);
            node.retryTimer = null;
        }
    };

    // Schedule a reconnect with exponential backoff and jitter. The previous
    // behaviour reconnected immediately and without limit, so a hub that kept
    // dropping the device produced a tight reconnect loop that starved the
    // Node-RED event loop and hammered the service.
    function scheduleRetry(node) {
        if (node.closing || node.retryTimer) {
            return;
        }
        var base = Number(node.retryInterval);
        if (!isFinite(base) || base <= 0) {
            base = 10;
        }
        var delay = Math.min(base * 1000 * Math.pow(2, Math.min(node.connectAttempts, 6)), MAX_RETRY_INTERVAL);
        // Full jitter over the lower half of the window, to avoid a thundering herd
        // when many devices reconnect at once.
        delay = Math.floor((delay / 2) + (Math.random() * (delay / 2)));
        node.log(node.deviceid + ' -> Retrying connection in ' + Math.round(delay / 1000) + ' seconds.');
        node.retryTimer = setTimeout(function () {
            node.retryTimer = null;
            startDevice(node);
        }, delay);
    };

    // Close all listeners
    function closeAll(node) {
        node.log(node.deviceid + ' -> Closing all clients.');
        try {
            node.twin.removeAllListeners();
            node.twin = null;
        } catch (err) {
            node.twin = null;
        }
        try {
            node.client.removeAllListeners();
            node.client.close((err,result) => {
                if (err) {
                    node.log(node.deviceid + ' -> Azure IoT Device Client close failed: ' + safeStringify(err));
                } else {
                    node.log(node.deviceid + ' -> Azure IoT Device Client closed.');
                }
            });
            node.client = null;
        } catch (err) {
            node.client = null;
        }
        node.methodResponses = [];
    };

    // Handle a message arriving on the node input.
    function handleInput(node, msg, done) {
        try {
            var payload = msg.payload;
            if (typeof payload === 'string') {
                // A malformed string used to throw straight out of the input
                // handler and take the flow down. Report it as a normal error.
                try {
                    payload = parseJson(payload);
                } catch (err) {
                    error(node, msg, node.deviceid + ' -> Invalid input: payload is a string but not valid JSON.');
                    return done();
                }
            } else {
                payload = sanitizePayload(payload, 0);
            }

            if (msg.topic === 'telemetry') {
                sendDeviceTelemetry(node, { payload: payload, timestamp: msg.timestamp }, msg.properties);
            } else if (msg.topic === 'property' && node.twin) {
                sendDeviceProperties(node, { payload: payload });
            } else if (msg.topic === 'response') {
                if (!payload || typeof payload !== 'object' ||
                    (typeof payload.requestId !== 'string' && typeof payload.requestId !== 'number')) {
                    error(node, msg, node.deviceid + ' -> Invalid method response: payload must be an object with a requestId.');
                    return done();
                }
                node.log(node.deviceid + ' -> Method response received with id: ' + payload.requestId);
                sendMethodResponse(node, { payload: payload });
            } else if (msg.topic === 'property') {
                error(node, msg, node.deviceid + ' -> Unable to send device properties, device not connected.');
            } else {
                error(node, msg, node.deviceid + ' -> Incorrect input. Must be of type \"telemetry\" or \"property\" or \"response\".');
            }
            done();
        } catch (err) {
            error(node, err, node.deviceid + ' -> Failed to process input message.');
            done();
        }
    };

    // Provision, connect and retrieve the twin. Retries on failure with backoff.
    function startDevice(node) {
        // Guard against overlapping start attempts: a disconnect event firing while
        // a start was already in flight used to spawn a second client.
        if (node.closing || node.starting) {
            return;
        }
        node.starting = true;

        provisionDevice(node)
            .then(function (options) {
                return connectDevice(node, options);
            })
            .then(function () {
                return retrieveTwin(node);
            })
            .then(function () {
                node.log(node.deviceid + ' -> Device twin retrieved.');
                node.starting = false;
                node.connectAttempts = 0;
            })
            .catch(function (err) {
                node.starting = false;
                node.connectAttempts++;
                error(node, err, node.deviceid + ' -> Device start failed.');
                setStatus(node, statusEnum.error);
                closeAll(node);
                scheduleRetry(node);
            });
    };

    // Provision the client
    function provisionDevice(node) {
        // Set status
        setStatus(node, statusEnum.provisioning);

        // Return a promise to enable retry
        return new Promise((resolve,reject) => {
            try {
                // Log the start
                node.log(node.deviceid + ' -> Initiate IoT Device settings.');

                // Validate every configured value that is later concatenated into a
                // connection string, before it is used for anything.
                validateConnectionStringValue('Device ID', node.deviceid, DEVICEID_PATTERN, MAX_DEVICEID_LENGTH);
                if (node.connectiontype === "dps") {
                    validateConnectionStringValue('Scope ID', node.scopeid, SCOPEID_PATTERN, MAX_DEVICEID_LENGTH);
                } else {
                    validateConnectionStringValue('IoT Hub hostname', node.iothub, HOSTNAME_PATTERN, MAX_HOSTNAME_LENGTH);
                }
                if (node.gatewayHostname) {
                    validateConnectionStringValue('Gateway hostname', node.gatewayHostname, HOSTNAME_PATTERN, MAX_HOSTNAME_LENGTH);
                }
                if (node.authenticationmethod === "sas") {
                    validateConnectionStringValue('SAS key', node.saskey, SASKEY_PATTERN, MAX_SASKEY_LENGTH);
                }

                // Set the security properties
                var options = {};
                if (node.authenticationmethod === "x509") {
                    node.log(node.deviceid + ' -> Validating device certificates.');
                    // Set cert options
                    // verify PEM work around for SDK issue
                    if (!verifyCertificatePem(node, node.cert))
                    {
                        // Must return: without it the rejection was ignored here and
                        // provisioning carried on with empty credentials, defeating
                        // the certificate check entirely.
                        return reject(new Error('Invalid certificates.'));
                    }
                    if (typeof node.key !== 'string' || node.key.length === 0) {
                        return reject(new Error('Missing X.509 private key.'));
                    }
                    options = {
                        cert : node.cert,
                        key : node.key,
                        passphrase : node.passphrase
                    };
                };

                // Check if connection type is dps, if not skip the provisioning step
                if (node.connectiontype === "dps") {

                    // Set provisioning protocol to selected (default to AMQP-WS)
                    var provisioningProtocol = (node.protocol === "amqp") ? ProvisioningProtocols.amqp :
                        (node.protocol === "amqpWs") ? ProvisioningProtocols.amqpWs :
                        (node.protocol === "mqtt") ? ProvisioningProtocols.mqtt :
                        (node.protocol === "mqttWs") ? ProvisioningProtocols.mqttWs :
                        ProvisioningProtocols.amqpWs;

                    // Set security client based on SAS or X.509
                    var saskey = (node.enrollmenttype === "group") ? computeDerivedSymmetricKey(node.saskey, node.deviceid) : node.saskey;
                    var provisioningSecurityClient =
                        (node.authenticationmethod === "sas") ? new SecurityClient.sas(node.deviceid, saskey) :
                            new SecurityClient.x509(node.deviceid, options);

                    // Create provisioning client
                    var provisioningClient = ProvisioningDeviceClient.create(GlobalProvisoningEndpoint, node.scopeid, new provisioningProtocol(), provisioningSecurityClient);

                    // set the provisioning payload (for custom allocation)
                    var payload = {};
                    if (node.DPSpayload) {
                        // Turn payload into JSON
                        try {
                            payload = parseJson(node.DPSpayload);
                            node.log(node.deviceid + ' -> DPS Payload added.');
                        } catch (err) {
                            node.warn(node.deviceid + ' -> DPS payload is not valid JSON and was ignored.');
                        }
                    }

                    // Register the device.
                    node.log(node.deviceid + ' -> Provision IoT Device using DPS.');
                    provisioningClient.setProvisioningPayload(JSON.stringify(payload));
                    provisioningClient.register().then( result => {
                        try {
                            // The DPS response ends up in a connection string, so it
                            // is validated like any other untrusted input.
                            var assignedHub = validateConnectionStringValue('Assigned IoT Hub hostname', result.assignedHub, HOSTNAME_PATTERN, MAX_HOSTNAME_LENGTH);
                            var assignedDeviceId = validateConnectionStringValue('Assigned device ID', result.deviceId, DEVICEID_PATTERN, MAX_DEVICEID_LENGTH);

                            // Process provisioning details
                            node.log(node.deviceid + ' -> DPS registration succeeded.');
                            node.log(node.deviceid + ' -> Assigned hub: ' + assignedHub);
                            var msg = {};
                            msg.topic = 'provisioning';
                            msg.deviceId = assignedDeviceId;
                            msg.payload = sanitizePayload(JSON.parse(JSON.stringify(result)), 0);
                            node.send(msg);
                            node.iothub = assignedHub;
                            node.deviceid = assignedDeviceId;
                            setStatus(node, statusEnum.disconnected);
                            resolve(options);
                        } catch (err) {
                            error(node, err, node.deviceid + ' -> DPS returned an invalid registration result.');
                            setStatus(node, statusEnum.error);
                            reject(err);
                        }
                    }).catch( function(err) {
                        // Handle error
                        error(node, err, node.deviceid + ' -> DPS registration failed.');
                        setStatus(node, statusEnum.error);
                        reject(err);
                    });
                } else {
                    resolve(options);
                }
            } catch (err) {
                reject(new Error("Failed to provision device: " + redactText(err.message || String(err))));
            }
        });
    }

    // Initiate an IoT device node in node-red
    function connectDevice(node, options){
        // Set status
        setStatus(node, statusEnum.connecting);

        // Return the promise
        return new Promise((resolve,reject) => {
            try {
                // Set provisioning protocol to selected (default to AMQP-WS)
                var deviceProtocol = (node.protocol === "amqp") ? Protocols.amqp :
                (node.protocol === "amqpWs") ? Protocols.amqpWs :
                (node.protocol === "mqtt") ? Protocols.mqtt :
                (node.protocol === "mqttWs") ? Protocols.mqttWs :
                Protocols.amqpWs;

                // Re-validate: node.iothub and node.deviceid may have been replaced
                // by the DPS registration result since provisioning ran.
                var iothub = validateConnectionStringValue('IoT Hub hostname', node.iothub, HOSTNAME_PATTERN, MAX_HOSTNAME_LENGTH);
                var deviceid = validateConnectionStringValue('Device ID', node.deviceid, DEVICEID_PATTERN, MAX_DEVICEID_LENGTH);

                // Set the client connection string and options
                var connectionString = 'HostName=' + iothub + ';DeviceId=' + deviceid;
                // Finalize the connection string
                var saskey = (node.connectiontype === "dps" && node.enrollmenttype === "group" && node.authenticationmethod === 'sas') ? computeDerivedSymmetricKey(node.saskey, node.deviceid) : node.saskey;
                if (node.authenticationmethod === 'sas') {
                    validateConnectionStringValue('SAS key', saskey, SASKEY_PATTERN, MAX_SASKEY_LENGTH);
                    connectionString = connectionString + ';SharedAccessKey=' + saskey;
                } else {
                    connectionString = connectionString + ';x509=true';
                }

                // Update options
                if (node.gatewayHostname) {
                    var gateway = validateConnectionStringValue('Gateway hostname', node.gatewayHostname, HOSTNAME_PATTERN, MAX_HOSTNAME_LENGTH);
                    node.log(node.deviceid + ' -> Connect through gateway: ' + gateway);
                    // Only override the trust anchors when a CA was actually
                    // supplied; an empty value would leave the SDK without a usable
                    // trust store instead of falling back to the default one.
                    if (typeof node.ca === 'string' && node.ca.trim().length > 0) {
                        options.ca = node.ca;
                    } else {
                        node.warn(node.deviceid + ' -> No gateway CA certificate configured; using the default trust store.');
                    }
                    connectionString = connectionString + ';GatewayHostName=' + gateway;
                }

                // Define the client
                node.client = Client.fromConnectionString(connectionString, deviceProtocol);

                // Add pnp modelid to options
                if (node.pnpModelid) {
                    options.modelId = node.pnpModelid;
                    node.log(node.deviceid + ' -> Set PnP Model ID: ' + node.pnpModelid);
                }
            } catch (err) {
                setStatus(node, statusEnum.error);
                return reject(err);
            }

            // Set the options first and then open the connection
            node.client.setOptions(options).then( result => {
                node.client.open().then( result => {
                    // Setup the client
                    // React or errors
                    node.client.on('error', function (err) {
                        error(node, err, node.deviceid + ' -> Device Client error.');
                        setStatus(node, statusEnum.error);
                    });

                    // React on disconnect and try to reconnect, with backoff.
                    node.client.on('disconnect', function (err) {
                        error(node, err, node.deviceid + ' -> Device Client disconnected.');
                        setStatus(node, statusEnum.disconnected);
                        closeAll(node);
                        node.connectAttempts++;
                        scheduleRetry(node);
                    });

                    // Listen to commands for defined direct methods
                    for (let method in node.methods) {
                        var mthd = node.methods[method] ? node.methods[method].name : null;
                        if (typeof mthd !== 'string' || mthd.length === 0) {
                            node.warn(node.deviceid + ' -> Skipping direct method with an empty name.');
                            continue;
                        }
                        node.log(node.deviceid + ' -> Adding synchronous command: ' + mthd);
                        // Define the method on the client
                        node.client.onDeviceMethod(mthd, function(request, response) {
                            node.log(node.deviceid + ' -> Command received: ' + request.methodName);
                            node.debug(node.deviceid + ' -> Command payload: ' + safeStringify(request.payload));
                            node.send({payload: request, topic: "command", deviceId: node.deviceid});

                            // Now wait for the response
                            getResponse(node, request.requestId).then( message => {
                                var rspns = message.payload;
                                // The response is produced by the flow and may be
                                // anything; validate it before handing it to the SDK
                                // so a malformed one cannot crash the node.
                                var status = Number(rspns && rspns.status);
                                if (!isFinite(status) || status < 100 || status > 599) {
                                    status = 500;
                                    node.warn(node.deviceid + ' -> Method response had no valid status, defaulting to 500.');
                                }
                                node.log(node.deviceid + ' -> Method response status: ' + status);
                                node.debug(node.deviceid + ' -> Method response payload: ' + safeStringify(rspns && rspns.payload));
                                response.send(status, (rspns && rspns.payload !== undefined) ? rspns.payload : null, function(err) {
                                    if (err) {
                                    node.log(node.deviceid + ' -> Failed sending method response: ' + redactText(String(err)));
                                    } else {
                                    node.log(node.deviceid + ' -> Successfully sent method response: ' + request.methodName);
                                    }
                                });
                            })
                            .catch( function(err){
                                error(node, err, node.deviceid + ' -> Failed sending method response: \"' + request.methodName + '\".');
                            });
                        });
                    };

                    // Start listening to C2D messages
                    node.log(node.deviceid + ' -> Listening to C2D messages');
                    // Define the message listener
                    node.client.on('message', function (msg) {
                        // A malformed cloud-to-device message must not be able to
                        // take the node down, and must still be settled afterwards.
                        try {
                            node.debug(node.deviceid + ' -> C2D message received.');
                            var message = {
                                messageId: msg ? msg.messageId : undefined,
                                data: (msg && msg.data !== null && msg.data !== undefined) ? msg.data.toString('utf8') : null,
                                properties: msg ? msg.properties : undefined
                            };
                            node.send({payload: message, topic: "message", deviceId: node.deviceid});
                        } catch (err) {
                            error(node, err, node.deviceid + ' -> Failed to process C2D message.');
                        }
                        try {
                            node.client.complete(msg, function (err) {
                                if (err) {
                                    error(node, err, node.deviceid + ' -> C2D Message complete error.');
                                } else {
                                    node.log(node.deviceid + ' -> C2D Message completed.');
                                }
                            });
                        } catch (err) {
                            error(node, err, node.deviceid + ' -> C2D Message complete error.');
                        }
                    });

                    node.log(node.deviceid + ' -> Device client connected.');
                    setStatus(node, statusEnum.connected);
                    resolve(null);
                }).catch( function(err) {
                    error(node, err, node.deviceid + ' -> Device client open failed.');
                    setStatus(node, statusEnum.error);
                    reject(err);
                });
            }).catch( function(err) {
                error(node, err, node.deviceid + ' -> Device options setting failed.');
                setStatus(node, statusEnum.error);
                reject(err);
            });

        });
    };

    // Get the device twin
    function retrieveTwin(node){
        // Set the options first and then open the connection
        node.log(node.deviceid + ' -> Retrieve device twin.');
        return new Promise((resolve,reject) => {
            node.client.getTwin().then( result => {
                node.log(node.deviceid + ' -> Device twin created.');
                node.twin = result;
                // Twin contents can hold device secrets; keep the dump out of the
                // default log level.
                node.debug(node.deviceid + ' -> Twin contents: ' + safeStringify(node.twin.properties));
                // Send the twin properties to Node Red
                var msg = {};
                msg.topic = 'property';
                msg.deviceId = node.deviceid;
                msg.payload = sanitizePayload(JSON.parse(JSON.stringify(node.twin.properties)), 0);
                node.send(msg);

                // Get the desired properties
                node.twin.on('properties.desired', function(payload) {
                    try {
                        node.debug(node.deviceid + ' -> Desired properties received: ' + safeStringify(payload));
                        var msg = {};
                        msg.topic = 'property';
                        msg.deviceId = node.deviceid;
                        // Desired properties arrive from the cloud; strip
                        // prototype-polluting keys before passing them on.
                        msg.payload = sanitizePayload(payload, 0);
                        node.send(msg);
                    } catch (err) {
                        error(node, err, node.deviceid + ' -> Failed to process desired properties.');
                    }
                });
                // Without this the promise never settled and the caller hung.
                resolve(null);
            }).catch(err => {
                error(node, err, node.deviceid + ' -> Device twin retrieve failed.');
                reject(err);
            });
        })
    };

    // Send messages to IoT platform (Transparant Edge, IoT Hub, IoT Central)
    function sendDeviceTelemetry(node, message, properties) {
        if (validateMessage(message.payload)){
            if (message.timestamp && isNaN(Date.parse(message.timestamp))) {
                error(node, message, node.deviceid + ' -> Invalid telemetry format: if present, timestamp must be in ISO format (e.g., YYYY-MM-DDTHH:mm:ss.sssZ).');
            } else {
                // Create message and set encoding and type
                var msg = new Message(JSON.stringify(message.payload));
                // Check if properties set and add if so
                if (properties && typeof properties === 'object'){
                    for (let property in properties) {
                        var item = properties[property];
                        if (!item || typeof item.key !== 'string' || item.key.length === 0) {
                            node.warn(node.deviceid + ' -> Skipping message property without a valid key.');
                            continue;
                        }
                        msg.properties.add(item.key, String(item.value === undefined ? '' : item.value));
                    }
                }
                msg.contentEncoding = 'utf-8';
                msg.contentType = 'application/json';
                // Send the message
                if (node.client) {
                    node.client.sendEvent(msg, function(err, res) {
                        if(err) {
                            error(node, err, node.deviceid + ' -> An error ocurred when sending telemetry.');
                            setStatus(node, statusEnum.error);
                        } else {
                            node.debug(node.deviceid + ' -> Telemetry sent: ' + safeStringify(message.payload));
                            setStatus(node, statusEnum.connected);
                        }
                    });
                } else {
                    error(node, message, node.deviceid + ' -> Unable to send telemetry, device not connected.');
                    setStatus(node, statusEnum.error);
                }
            }
        } else {
            error(node, message, node.deviceid + ' -> Invalid telemetry format.');
        }
    };


    // Send device reported properties.
    function sendDeviceProperties(node, message) {
        if (node.twin) {
            node.twin.properties.reported.update(message.payload, function (err) {
                if (err) {
                    error(node, err, node.deviceid + ' -> Sending device properties failed.');
                    setStatus(node, statusEnum.error);
                } else {
                    node.debug(node.deviceid + ' -> Device properties sent: ' + safeStringify(message.payload));
                    setStatus(node, statusEnum.connected);
                }
            });
        }
        else {
            error(node, message, node.deviceid + ' -> Unable to send device properties, device not connected.');
        }
    };

    // Send device direct method response.
    function sendMethodResponse(node, message) {
        // Push the reponse to the array
        var methodResponse = message.payload;
        node.log(node.deviceid + ' -> Creating response for command: ' + methodResponse.methodName);
        // Evict stale entries so that responses nobody is waiting for cannot
        // accumulate until the process runs out of memory.
        pruneMethodResponses(node);
        node.methodResponses.push(
            {requestId: methodResponse.requestId, response: message, timestamp: Date.now()}
        );
        pruneMethodResponses(node);
    };

    // Get method response using promise, and retry, and slow backoff
    function getResponse(node, requestId){
        var retries = 20;
        var timeOut = 1000;
        // Retrieve client using progressive promise to wait for method response
        var promise = Promise.reject();
        for(var i=1; i <= retries; i++) {
            promise = promise.catch( function() {
                    var methodResponse = node.methodResponses.find(function(m){return m.requestId === requestId});
                    if (methodResponse){
                        // get the response and clean the array
                        node.methodResponses.splice(node.methodResponses.findIndex(function(m){return m.requestId === requestId}),1);
                        return methodResponse.response;
                    }
                    else {
                        throw new Error(node.deviceid + ' -> Method Response not received..');
                    }
                })
                .catch(function rejectDelay(reason) {
                    return new Promise(function(resolve, reject) {
                        setTimeout(reject.bind(null, reason), timeOut * ((i % 10) + 1));
                    });
                });
        }
        return promise;
    };

    // @returns true if message object is valid, i.e., a map of field names to numbers, strings and booleans.
    function validateMessage(message, depth) {
        depth = depth || 0;
        // Bound the recursion: a deeply nested payload used to be able to exhaust
        // the stack and take the process down.
        if (depth > MAX_PAYLOAD_DEPTH) {
            return false;
        }
        if (!message || typeof message !== 'object') {
            return false;
        }
        for (let field in message) {
            if (!Object.prototype.hasOwnProperty.call(message, field)) {
                continue;
            }
            var value = message[field];
            if (typeof value !== 'number' && typeof value !== 'string' && typeof value !== 'boolean' && value !== null) {
                if (typeof value === 'object')
                {
                    // The result of this call used to be discarded, so any nested
                    // object made the whole payload validate regardless of contents.
                    if (!validateMessage(value, depth + 1)) {
                        return false;
                    }
                }
                else {
                    return false;
                }
            }
        }
        return true;
    };

    // Registration of the node into Node-RED
    RED.nodes.registerType("azureiotdevice", AzureIoTDevice, {
        defaults: {
            deviceid: {value: ""},
            pnpModelid: {value: ""},
            connectiontype: {value: ""},
            authenticationmethod: {value: ""},
            enrollmenttype: {value: ""},
            iothub: {value: ""},
            isIotcentral: {value: false},
            scopeid: {value: ""},
            saskey: {value: ""},
            certname: {value: ""},
            keyname: {value: ""},
            passphrase: {value:""},
            protocol: {value: ""},
            retryInterval: {value: 10},
            methods: {value: []},
            DPSpayload: {value: ""},
            isDownstream: {value: false},
            gatewayHostname: {value: ""},
            caname: {value:""},
            cert: {type:"text"},
            key: {type:"text"},
            ca: {type:"text"}
        }
    });

}
