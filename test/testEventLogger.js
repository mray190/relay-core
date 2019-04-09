'use strict'

/*
 * Copyright (c) 2018, Arm Limited and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const WigWagAuthorizer = require('../index.js').WigWagAuthorizer
const EventLogger = require('../index.js').EventLogger
const expect = require('expect.js')
const should = require('should')
const shouldPromised = require('should-promised')
const fs = require('fs')

describe('EventLogger', function() {
    it('should work', function() {
        let authorizer = new WigWagAuthorizer({
            relayID: 'WWRL000000',
            relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.client.key.pem'),
            relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.client.cert.pem')
        })
        let eventLogger = new EventLogger('http://localhost:8585', authorizer)
        
        return eventLogger.logEvent('resource123', 'motion', Math.random())
    })
})
