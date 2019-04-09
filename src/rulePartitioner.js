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

const RingState = require('./partitioner').RingState
const HashRing = require('./partitioner').HashRing

class RulePartitioner {
    constructor(nodeID) {
        this.nodeID = nodeID
        this.hashRing = new HashRing(nodeID)

        this.updateRelays(new Set([ ]))
    }

    updateRelays(reachableRelaySet) {
        let tokens = { }

        for(let nodeID of reachableRelaySet) {
            tokens[nodeID] = {
                version: 0,
                tokens: [ this.hashRing.getToken(nodeID) ]
            }
        }

        tokens[this.nodeID] = {
            version: 0,
            tokens: [ this.hashRing.getToken(this.nodeID) ]
        }

        this.hashRing.getRingState().setTokens(tokens)
    }

    getRuleExecutor(ruleID) {
        return this.hashRing.getPreferenceList(ruleID).sort()[0]
    }

    isExecutedByMe(ruleID) {
        return this.getRuleExecutor(ruleID) == this.nodeID
    }
}

module.exports = RulePartitioner