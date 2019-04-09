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

const request = require('request')
const url = require('url')

class EventLogger {
    constructor(cloudURL, wigwagAuthorizer) {
        this.cloudURL = cloudURL
        this.wigwagAuthorizer = wigwagAuthorizer
    }
    
    logEvent(resourceID, eventType, eventData) {
        return new Promise((resolve, reject) => {
            console.log(this.wigwagAuthorizer.generateRelayIdentityToken())
            request.put(url.resolve(this.cloudURL, '/history/events/'+encodeURIComponent(eventType)+'/'+encodeURIComponent(resourceID)), {
                headers: {
                    Authorization: this.wigwagAuthorizer.generateRelayIdentityToken()
                },
                body: {
                    eventData: eventData
                },
                json: true
            }, function(error, response, responseBody) {
                if(error) {
                    console.log(error)
                    reject(error)
                }
                else {
                    console.log(response.statusCode)
                    if(response.statusCode != 200) {
                        reject()
                    }
                    else {
                        resolve()
                    }
                }
            })
        })
    }
}

module.exports = EventLogger
