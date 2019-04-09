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

const crypto = require('crypto')
const math = require('mathjs')
const assert = require('assert')

const REPLICATION_FACTOR = 3
const HASH_RANGE_DIVISONS = 256
const TOKEN_FORMAT_REGEX = /[0-9a-zA-Z]{32}/
const NODE_ID_FORMAT_REGEX = /.+/

function bigNumberToBuffer(bigNumber, bufferSize) {
    let hexString = bigNumber.toHexadecimal().substring('0x'.length)

    if(hexString.length % 2 == 1) {
        hexString = '0' + hexString
    }

    let buffer = new Buffer(hexString, 'hex')

    if(bufferSize) {
        if(bufferSize >= buffer.length) {
            let tempBuffer = new Buffer(bufferSize)
            tempBuffer.fill(0)

            buffer.copy(tempBuffer, tempBuffer.length - buffer.length)

            buffer = tempBuffer
        }
        else {
            throw new Error('Buffer too long')
        }
    }

    return buffer
}

function bufferToBigNumber(buffer) {
    return math.bignumber('0x'+buffer.toString('hex'))
}

class HashStrategy {
    constructor() {
    }

    hash(value) {
    }

    hashLength() {
    }

    serialize() {
    }

    deserialize() {
    }
}

class TokenStrategy {
    constructor() {
    }

    token(key) {
    }

    tokenLength() {
    }

    serialize() {
    }

    deserialize() {
    }
}

class MD5HashStrategy extends HashStrategy {
    hash(value) {
        let hashHex = crypto.createHash('md5').update(value).digest('hex')
        return math.bignumber('0x'+hashHex)
    }

    hashLength() {
        return 128
    }

    serialize(deserializedHash) {
        let serialized = deserializedHash.toHexadecimal()

        return serialized.substring('0x'.length)
    }

    deserialize(serializedHash) {
        return math.bignumber('0x'+serializedHash)
    }
}

class MD5TokenStrategy extends TokenStrategy {
    token(key) {
        let tokenHex = crypto.createHash('md5').update(key).digest('hex')
        return math.bignumber('0x'+tokenHex)
    }

    tokenLength() {
        return 128
    }

    serialize(deserializedToken) {
        let serialized = deserializedToken.toHexadecimal()

        return serialized.substring('0x'.length)
    }

    deserialize(serializedToken) {
        return math.bignumber('0x'+serializedToken)
    }
}

class RingState {
    constructor(tokenRangeMin, tokenRangeMax) {
        if(!tokenRangeMin) {
            tokenRangeMin = math.bignumber(0)
        }

        if(!tokenRangeMax) {
            tokenRangeMax = math.bignumber(2).pow(128)
        }

        assert(typeof tokenRangeMin.toHexadecimal == 'function' && typeof tokenRangeMax.toHexadecimal == 'function' && tokenRangeMin.comparedTo(tokenRangeMax) < 0, 'min must be less than max')

        this.tokenRangeMin = tokenRangeMin
        this.tokenRangeMax = tokenRangeMax
        this.version = { }
        this.tokens = { }
    }

    setTokens(tokens) {
        assert(tokens != null && typeof tokens == 'object' && !Array.isArray(tokens), 'tokens must be an object')

        let versionMap = { }
        let tokensMap = { }

        for(let node in tokens) {
            assert(node.length > 0, 'node id length must be greater than zero')
            assert(tokens[node] != null && typeof tokens[node] == 'object', 'tokens values must be objects')
            assert(typeof tokens[node].version == 'number' && tokens[node].version%1 == 0 && tokens[node].version >= 0, 'version must be a positive integer or zero')
            assert(Array.isArray(tokens[node].tokens), 'tokens property must be an array')

            for(let token of tokens[node].tokens) {
                assert(typeof token.toHexadecimal == 'function' && token.isInteger() && token.comparedTo(this.tokenRangeMin) >= 0 && token.comparedTo(this.tokenRangeMax) < 0, 'token must be inside token range')
            }

            versionMap[node] = tokens[node].version
            tokensMap[node] = tokens[node].tokens
        }

        this.version = versionMap
        this.tokens = tokensMap

        return this
    }

    getVersion() {
        return this.version
    }

    getTokens(nodeID) {
        return this.tokens[nodeID] || null
    }

    getSortedTokens() {
        let sortedTokens = [ ]

        for(let nodeID in this.tokens) {
            for(let token of this.tokens[nodeID]) {
                sortedTokens.push({ nodeID: nodeID, token: token })
            }
        }

        sortedTokens.sort((a, b) => {
            if(a.token.comparedTo(b.token) < 0) {
                return -1
            }
            else if(a.token.comparedTo(b.token) > 0) {
                return 1
            }
            else {
                if(a.nodeID < b.nodeID) {
                    return -1
                }
                else {
                    return 1
                }
            }
        })

        return sortedTokens
    }

    getTokenRingIterator(startToken) {
        if(!startToken) {
            startToken = this.tokenRangeMin
        }

        return new TokenRingIterator(startToken, this.getSortedTokens())
    }
}

class TokenRingIterator {
    constructor(startToken, sortedTokens) {
        this.firstTokenIndex = 0

        for(let i = 0; i < sortedTokens.length; i += 1) {
            if(startToken.comparedTo(sortedTokens[i].token) <= 0) {
                break
            }

            this.firstTokenIndex = (i + 1) % sortedTokens.length
        }

        this.currentOffset = 0
        this.sortedTokens = sortedTokens
    }

    hasNextToken() {
        return this.currentOffset < this.sortedTokens.length
    }

    nextToken() {
        if(!this.hasNextToken()) {
            throw new Error('Index out of bounds')
        }

        let token = this.sortedTokens[(this.firstTokenIndex + this.currentOffset) % this.sortedTokens.length]

        this.currentOffset += 1

        return token
    }
}

// Each server represents a physical node. Each physical node is assigned a certain number of tokens, which are value on the ring
// The ring is divided into Q evenly sized sections
// Given a replication factor of N
// A key will be replicated to at most N distinct physical nodes whose token values are closest to the key token on the ring in the
// clockwise direction
// Equivalently, the three consecutive nodes are responsible for that token range that the key maps to
class HashRing {
    constructor(nodeID, replicationFactor) {
        assert(typeof nodeID == 'string' && NODE_ID_FORMAT_REGEX.test(nodeID), 'invalid node id')
        assert(Math.log2(HASH_RANGE_DIVISONS)%1 == 0, 'divisions must be a power of 2')
        assert(typeof replicationFactor == 'undefined' || typeof replicationFactor == 'number' && replicationFactor % 1 == 0 && replicationFactor >= 1, 'replication factor must be a positive integer')

        this.nodeID = nodeID
        this.tokens = 1
        this.tokenStrategy = new MD5TokenStrategy()
        this.tokenRangeMin = math.bignumber(0)
        this.tokenRangeMax = math.bignumber(2).pow(this.tokenStrategy.tokenLength())
        this.divisionSize = math.bignumber(2).pow(this.tokenStrategy.tokenLength() - Math.log2(HASH_RANGE_DIVISONS))
        this.ringState = new RingState(this.tokenRangeMin, this.tokenRangeMax)
        this.replicationFactor = typeof replicationFactor == 'undefined' ? REPLICATION_FACTOR : replicationFactor
    }

    getRingState() {
        return this.ringState
    }

    updateRingState(otherRingState) {
        // if there are any token set versions that are higher in the other ring state they override
        // ours
        try {
            assert(otherRingState instanceof RingState, 'otherRingState must be an instance of RingState')
        }
        catch(error) {
            return Promise.reject(error)
        }

        let ringStatePatch = { }

        // the ringState patch represents that changes that need to be applied to our ring state based on the new ring state information
        for(let node in otherRingState.getVersion()) {
            // if we have never heard of this node (not inside our version vector) or if our version of that node's token assignments are out of date, patch our token information
            // for that node
            if(!this.ringState.getVersion().hasOwnProperty(node) || this.ringState.getVersion()[node] < otherRingState.getVersion()[node]) {
                ringStatePatch[node] = {
                    tokens: otherRingState.getTokens(node),
                    version: otherRingState.getVersion()[node]
                }
            }
        }

        // this implies that the token information version from this node that the other node knew about
        // was higher than the version we have for ourselves. This is only possible if this node's data
        // was reset or wiped. Either way, we accept this new version number + 1 as the most up to date version number
        // for this node's token assignment.
        if(ringStatePatch.hasOwnProperty(this.nodeID)) {
            ringStatePatch[this.nodeID].tokens = this.ringState.getTokens(this.nodeID) || ringStatePatch[this.nodeID].tokens
            ringStatePatch[this.nodeID].version = ringStatePatch[this.nodeID].version + 1
        }

        // if any updates need to happen as a result of this new ring state information,
        // then enter this section to update the backing store and in memory ring state object
        // otherwise, there is nothing to do here so exit
        if(Object.keys(ringStatePatch).length > 0) {
            // if there is any node in our ring state object
            // whose token assignment was not updated by the new ring state information
            // place this into the ring state patch. The ring state patch now represents
            // the total updated ring state to be applied to the ring state object
            for(let node in this.ringState.getVersion()) {
                if(!ringStatePatch.hasOwnProperty(node)) {
                    ringStatePatch[node] = {
                        tokens: this.ringState.getTokens(node),
                        version: this.ringState.getVersion()[node]
                    }
                }
            }

            let version = { }

            for(let node in ringStatePatch) {
                version[node] = ringStatePatch[node].version
            }

            this.ringState.setTokens(ringStatePatch)
        }
    }

    getHashRange() {
        return {
            min: this.tokenRangeMin,
            max: this.tokenRangeMax
        }
    }

    getRangeDivisions() {
        return HASH_RANGE_DIVISONS
    }

    getRandomToken() {
        let randomBuffer = crypto.randomBytes(this.tokenStrategy.tokenLength()/8)

        return bufferToBigNumber(randomBuffer)
    }

    generateTokens() {
        let tokenSeparation = math.floor(math.divide(this.tokenRangeMax, this.tokens))
        let min = this.getRandomToken()
        let newTokens = [  ]

        // need to recalculate the tokens
        while(newTokens.length < this.tokens) {
            let offset = math.mod(math.floor(math.multiply(tokenSeparation, math.bignumber(Math.random()))), tokenSeparation)
            let token = math.mod(min.add(offset), this.tokenRangeMax)

            newTokens.push(token)

            min = math.mod(min.add(tokenSeparation), this.tokenRangeMax)
        }

        return newTokens
    }
    
    getReplicationFactor() {
        return this.replicationFactor
    }

    getPreferenceList(key) {
        try {
            assert(typeof key == 'string' && key.length > 0)
        }
        catch(error) {
            return Promise.reject(error)
        }

        let preferenceList = new Set()
        let token = this.tokenStrategy.token(key)
        let tokenDivisionIndex = math.floor(math.divide(token, this.divisionSize))
        let tokenDivisionStart = math.multiply(this.divisionSize, tokenDivisionIndex)
        let tokenRingIterator = this.ringState.getTokenRingIterator(tokenDivisionStart)

        while(tokenRingIterator.hasNextToken()) {
            let nextToken = tokenRingIterator.nextToken()
            let nodeID = nextToken.nodeID

            preferenceList.add(nodeID)

            if(preferenceList.size == this.getReplicationFactor()) {
                break
            }
        }

        let preferenceListAsArray = [ ]

        for(let nodeID of preferenceList) {
            preferenceListAsArray.push(nodeID)
        }

        return preferenceListAsArray
    }

    getPreferenceLists() {
        // figure out preference lists for each partition
        let preferenceLists = [ ]
        let ringStructure = [ ]
        let tokenRingIterator = this.ringState.getTokenRingIterator(this.tokenRangeMin)

        let getPartitionPreferenceList = (partitionStart) => {
            let first = 0

            // find position of division start
            while(first < ringStructure.length) {
                if(partitionStart.comparedTo(ringStructure[first].token) < 0) {
                    break
                }
                else if(partitionStart.comparedTo(ringStructure[first].token) > 0) {
                    first += 1
                }
                else {
                    break
                }
            }

            if(first == ringStructure.length) {
                first = 0
            }

            // get next replicationFactor unique nodes
            let preferenceList = new Set()
            let currentIndex = first

            for(let i = 0; i < ringStructure.length && preferenceList.size < this.getReplicationFactor(); i += 1) {
                let nextTokenPair = ringStructure[currentIndex]

                preferenceList.add(nextTokenPair.node)

                currentIndex = (currentIndex + 1) % ringStructure.length
            }

            let preferenceListAsList = [ ]

            for(let node of preferenceList) {
                preferenceListAsList.push(node)
            }

            return preferenceListAsList
        }

        while(tokenRingIterator.hasNextToken()) {
            let nextToken = tokenRingIterator.nextToken()

            ringStructure.push(nextToken)
        }

        let currentMin = math.bignumber(this.tokenRangeMin)

        for(let i = 0; i < this.getRangeDivisions(); i += 1) {
            preferenceLists.push(getPartitionPreferenceList(currentMin))

            currentMin = currentMin.add(this.divisionSize)
        }

        return preferenceLists
    }

    getPartitionNumber(key) {
        let token = this.tokenStrategy.token(key)
        let tokenDivisionIndex = math.floor(math.divide(token, this.divisionSize))

        return tokenDivisionIndex.toNumber()
    }

    getToken(key) {
        return this.tokenStrategy.token(key)
    }
    
    parseToken(t) {
        let token = math.bignumber(t)
        
        assert(typeof token.toHexadecimal == 'function' && token.isInteger() && token.comparedTo(this.tokenRangeMin) >= 0 && token.comparedTo(this.tokenRangeMax) < 0, 'token must be inside token range')
        
        return token
    }

    getNodePartitions(nodeID) {
        let partitions = [ ]
        let preferenceLists = this.getPreferenceLists()

        for(let i = 0; i < preferenceLists.length; i+= 1) {
            if(preferenceLists[i].indexOf(nodeID) != -1) {
                partitions.push(i)
            }
        }

        return partitions
    }

    getMyPartitions() {
        return this.getNodePartitions(this.nodeID)
    }
}

module.exports = {
    HashRing: HashRing,
    RingState: RingState,
    MD5TokenStrategy: MD5TokenStrategy,
    getReplicationFactor: () => { return REPLICATION_FACTOR }
}