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
const partitioner = require('../index.js').partitioner
const RingState = partitioner.RingState
const HashRing = partitioner.HashRing
const MD5TokenStrategy = partitioner.MD5TokenStrategy
const expect = require('expect.js')
const should = require('should')
const shouldPromised = require('should-promised')
const fs = require('fs')
const jwt = require('jsonwebtoken')
const math = require('mathjs')
const assert = require('assert')

const hashedPassword = '$2a$10$.ueD8J3iGjgojZi3epFyeuFKaQL64QLO/BPMDzG4XLuzB/ypjLytK' // 'password' -> hashed

class StubTokenStrategy extends MD5TokenStrategy {
    constructor(mappings) {
        super()

        this.mappings = mappings
    }

    token(value) {
        assert(this.mappings.hasOwnProperty(value), 'domain must be explicitly defined in stub token strategy')

        return this.mappings[value]
    }
}

describe('WigWagAuthorizer', function() {
    describe('#isRelayAuthorized', function() {
        it('should fulfill to true or false if siblings exist in those keys', function() {
            let ddbStub = {
                cloud: {
                    get(key) {
                        return Promise.resolve({
                            siblings: [
                                JSON.stringify({
                                    WWRL000001: { }
                                }),
                                JSON.stringify({
                                    WWRL000003: { }
                                })
                            ]
                        })
                    }
                }
            }

            let authorizer = new WigWagAuthorizer({
                relayID: 'WWRL000000',
                relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.key.pem'),
                relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.cert.pem'),
                ddb: ddbStub
            })

            return authorizer.isRelayAuthorized('WWRL000001').should.be.fulfilledWith(true).then(function() {
                return authorizer.isRelayAuthorized('WWRL000002').should.be.fulfilledWith(false)
            }).then(function() {
                return authorizer.isRelayAuthorized('WWRL000003').should.be.fulfilledWith(true)
            })
        })

        it('should fulfill to false if the key does not exist', function() {
            let ddbStub = {
                cloud: {
                    get(key) {
                        return Promise.resolve(null)
                    }
                }
            }

            let authorizer = new WigWagAuthorizer({
                relayID: 'WWRL000000',
                relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.key.pem'),
                relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.cert.pem'),
                ddb: ddbStub
            })

            return authorizer.isRelayAuthorized('WWRL000001').should.be.fulfilledWith(false).then(function() {
                return authorizer.isRelayAuthorized('WWRL000002').should.be.fulfilledWith(false)
            }).then(function() {
                return authorizer.isRelayAuthorized('WWRL000003').should.be.fulfilledWith(false)
            })
        })

        it('should fulfill to false if the siblings list is empty', function() {
            let ddbStub = {
                cloud: {
                    get(key) {
                        return Promise.resolve({
                            siblings: [ ]
                        })
                    }
                }
            }

            let authorizer = new WigWagAuthorizer({
                relayID: 'WWRL000000',
                relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.key.pem'),
                relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.cert.pem'),
                ddb: ddbStub
            })

            return authorizer.isRelayAuthorized('WWRL000001').should.be.fulfilledWith(false).then(function() {
                return authorizer.isRelayAuthorized('WWRL000002').should.be.fulfilledWith(false)
            }).then(function() {
                return authorizer.isRelayAuthorized('WWRL000003').should.be.fulfilledWith(false)
            })
        })
    })

    describe('#generateAccessToken', function() {
        it('should return a jwt token if the credentials are correct', function() {
            let ddbStub = {
                cloud: {
                    get(key) {
                        return Promise.resolve({
                            siblings: [
                                JSON.stringify({
                                    hashedPassword: hashedPassword
                                })
                            ]
                        })
                    }
                }
            }

            let authorizer = new WigWagAuthorizer({
                relayID: 'WWRL000000',
                relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.key.pem'),
                relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.cert.pem'),
                ddb: ddbStub
            })

            return authorizer.generateAccessToken('email@email.com', 'password').then(function(accessToken) {
                jwt.decode(accessToken).issuerID.should.be.eql('WWRL000000')
            })
        })

        it('should return null if the credentials are incorrect', function() {
            let ddbStub = {
                cloud: {
                    get(key) {
                        return Promise.resolve({
                            siblings: [
                                JSON.stringify({
                                    hashedPassword: hashedPassword
                                })
                            ]
                        })
                    }
                }
            }

            let authorizer = new WigWagAuthorizer({
                relayID: 'WWRL000000',
                relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.key.pem'),
                relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.cert.pem'),
                ddb: ddbStub
            })

            return authorizer.generateAccessToken('email@email.com', 'password1').should.be.fulfilledWith(null)
        })

        it('should return null if the credentials are not stored for that user', function() {
            let ddbStub = {
                cloud: {
                    get(key) {
                        return Promise.resolve({
                            siblings: [
                            ]
                        })
                    }
                }
            }

            let authorizer = new WigWagAuthorizer({
                relayID: 'WWRL000000',
                relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.key.pem'),
                relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.cert.pem'),
                ddb: ddbStub
            })

            return authorizer.generateAccessToken('email@email.com', 'password1').should.be.fulfilledWith(null)
        })

        it('should return null if the credentials are not stored for that user', function() {
            let ddbStub = {
                cloud: {
                    get(key) {
                        return Promise.resolve(null)
                    }
                }
            }

            let authorizer = new WigWagAuthorizer({
                relayID: 'WWRL000000',
                relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.key.pem'),
                relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.cert.pem'),
                ddb: ddbStub
            })

            return authorizer.generateAccessToken('email@email.com', 'password1').should.be.fulfilledWith(null)
        })
    })

    describe('#decodeAccessToken', function() {
        it('should return the decoded token if it was issued by this relay', function() {
            let ddbStub = {
                cloud: {
                    get(key) {
                        return Promise.resolve({
                            siblings: [
                                JSON.stringify({
                                    hashedPassword: hashedPassword
                                })
                            ]
                        })
                    }
                }
            }

            let authorizer = new WigWagAuthorizer({
                relayID: 'WWRL000000',
                relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.key.pem'),
                relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.cert.pem'),
                ddb: ddbStub
            })

            return authorizer.generateAccessToken('email@email.com', 'password').then(function(accessToken) {
                return authorizer.decodeAccessToken(accessToken)
            }).then(function(decodedToken) {
                decodedToken.issuerID.should.be.eql('WWRL000000')
            })
        })

        it('should return the decoded token if it was issued by a relay whose public key is stored in the database', function() {
            let ddbStub = {
                cloud: {
                    get(key) {
                        if(key == 'wigwag.relays') {
                            return Promise.resolve({
                                siblings: [
                                    JSON.stringify({
                                        WWRL000001: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000001.server.cert.pem', 'utf8')
                                    })
                                ]
                            })
                        }
                        else {
                            return Promise.resolve({
                                siblings: [
                                    JSON.stringify({
                                        hashedPassword: hashedPassword
                                    })
                                ]
                            })
                        }
                    }
                }
            }

            let authorizer0 = new WigWagAuthorizer({
                relayID: 'WWRL000000',
                relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.key.pem', 'utf8'),
                relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000000.server.cert.pem', 'utf8'),
                ddb: ddbStub
            })

            let authorizer1 = new WigWagAuthorizer({
                relayID: 'WWRL000001',
                relayPrivateKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000001.server.key.pem', 'utf8'),
                relayPublicKey: fs.readFileSync('/home/jrife/Documents/relay-certs/walt-cloud/WWRL000001.server.cert.pem', 'utf8'),
                ddb: ddbStub
            })

            return authorizer1.generateAccessToken('email@email.com', 'password').then(function(accessToken) {
                return authorizer0.decodeAccessToken(accessToken)
            }).then(function(decodedToken) {
                decodedToken.issuerID.should.be.eql('WWRL000001')
            })
        })
    })
})

describe('Partitioner', function() {
    describe('RingState', function() {
        describe('#getSortedTokens', function() {
            it('should return a sorted list of tokens along the ring', function() {
                let ringState = new RingState(math.bignumber(0), math.bignumber(2).pow(128))

                ringState.setTokens({
                    'nodeA': {
                        version: 0,
                        tokens: [ math.bignumber(23) ]
                    },
                    'nodeB': {
                        version: 0,
                        tokens: [ math.bignumber(22) ]
                    },
                    'nodeC': {
                        version: 0,
                        tokens: [ math.bignumber(28) ]
                    },
                    'nodeD': {
                        version: 0,
                        tokens: [ math.bignumber(28), math.bignumber(1) ]
                    }
                })

                ringState.getSortedTokens().map(t => { return { nodeID: t.nodeID, token: t.token.toHexadecimal() } }).should.be.eql([
                    { nodeID: 'nodeD', token: math.bignumber(1).toHexadecimal() },
                    { nodeID: 'nodeB', token: math.bignumber(22).toHexadecimal() },
                    { nodeID: 'nodeA', token: math.bignumber(23).toHexadecimal() },
                    { nodeID: 'nodeC', token: math.bignumber(28).toHexadecimal() },
                    { nodeID: 'nodeD', token: math.bignumber(28).toHexadecimal() }
                ])
            })
        })

        describe('#getTokenRingIterator', function() {
            it('should traverse all tokens in the ring in order starting at the token that comes directly after the start point', function() {
                let ringState = new RingState(math.bignumber(0), math.bignumber(2).pow(128))

                ringState.setTokens({
                    'nodeA': {
                        version: 0,
                        tokens: [ math.bignumber(23) ]
                    },
                    'nodeB': {
                        version: 0,
                        tokens: [ math.bignumber(22) ]
                    },
                    'nodeC': {
                        version: 0,
                        tokens: [ math.bignumber(28) ]
                    },
                    'nodeD': {
                        version: 0,
                        tokens: [ math.bignumber(28), math.bignumber(1) ]
                    }
                })

                function traverseAll(iterator) {
                    let all = [ ]

                    while(iterator.hasNextToken()) {
                        all.push(iterator.nextToken())
                    }

                    return all.map(t => { return { nodeID: t.nodeID, token: t.token.toHexadecimal() } })
                }

                let ringIterator0 = ringState.getTokenRingIterator()
                let ringIterator1 = ringState.getTokenRingIterator(math.bignumber(19))
                let ringIterator2 = ringState.getTokenRingIterator(math.bignumber(22))
                let ringIterator3 = ringState.getTokenRingIterator(math.bignumber(28))
                let ringIterator4 = ringState.getTokenRingIterator(math.bignumber(1024))

                traverseAll(ringIterator0).should.be.eql([
                    { nodeID: 'nodeD', token: math.bignumber(1).toHexadecimal() },
                    { nodeID: 'nodeB', token: math.bignumber(22).toHexadecimal() },
                    { nodeID: 'nodeA', token: math.bignumber(23).toHexadecimal() },
                    { nodeID: 'nodeC', token: math.bignumber(28).toHexadecimal() },
                    { nodeID: 'nodeD', token: math.bignumber(28).toHexadecimal() }
                ])

                traverseAll(ringIterator1).should.be.eql([
                    { nodeID: 'nodeB', token: math.bignumber(22).toHexadecimal() },
                    { nodeID: 'nodeA', token: math.bignumber(23).toHexadecimal() },
                    { nodeID: 'nodeC', token: math.bignumber(28).toHexadecimal() },
                    { nodeID: 'nodeD', token: math.bignumber(28).toHexadecimal() },
                    { nodeID: 'nodeD', token: math.bignumber(1).toHexadecimal() }
                ])

                traverseAll(ringIterator2).should.be.eql([
                    { nodeID: 'nodeB', token: math.bignumber(22).toHexadecimal() },
                    { nodeID: 'nodeA', token: math.bignumber(23).toHexadecimal() },
                    { nodeID: 'nodeC', token: math.bignumber(28).toHexadecimal() },
                    { nodeID: 'nodeD', token: math.bignumber(28).toHexadecimal() },
                    { nodeID: 'nodeD', token: math.bignumber(1).toHexadecimal() }
                ])

                traverseAll(ringIterator3).should.be.eql([
                    { nodeID: 'nodeC', token: math.bignumber(28).toHexadecimal() },
                    { nodeID: 'nodeD', token: math.bignumber(28).toHexadecimal() },
                    { nodeID: 'nodeD', token: math.bignumber(1).toHexadecimal() },
                    { nodeID: 'nodeB', token: math.bignumber(22).toHexadecimal() },
                    { nodeID: 'nodeA', token: math.bignumber(23).toHexadecimal() }
                ])

                traverseAll(ringIterator4).should.be.eql([
                    { nodeID: 'nodeD', token: math.bignumber(1).toHexadecimal() },
                    { nodeID: 'nodeB', token: math.bignumber(22).toHexadecimal() },
                    { nodeID: 'nodeA', token: math.bignumber(23).toHexadecimal() },
                    { nodeID: 'nodeC', token: math.bignumber(28).toHexadecimal() },
                    { nodeID: 'nodeD', token: math.bignumber(28).toHexadecimal() }
                ])
            })
        })
    })

    describe('HashRing', function() {
        it('should throw an assertion error if the node ID is not valid', function() {
            // empty string
            should.throws(() => { new HashRing('') })
            // non string value
            should.throws(() => { new HashRing(null) })
            should.throws(() => { new HashRing(3) })
        })
    })

    describe('#generateTokens', function() {
        it('should generate several spaced out tokens', function() {
            let hashRing = new HashRing('nodeA')
            let tokens = hashRing.generateTokens()

            tokens.length.should.be.eql(1)
            tokens.forEach(t => {
                t.toHexadecimal().should.match(/0x[0-9a-zA-Z]{1,32}/)
            })
        })
    })

    describe('#updateRingState', function() {
        it('should throw an assertion error if input is not a RingState object', function() {
            let hashRing = new HashRing('nodeA')

            return hashRing.updateRingState(null).should.be.rejected()
        })

        it('should merge in token assignment information from another node if we did not previously know about that node', function() {
            let hashRing = new HashRing('nodeA')

            hashRing.getRingState().getVersion().should.be.eql({ })
            should.equal(hashRing.getRingState().getTokens('nodeB'), null)

            let ringState = new RingState(hashRing.getHashRange().min, hashRing.getHashRange().max)

            ringState.setTokens({
                nodeB: {
                    version: 1,
                    tokens: [ math.bignumber(89), math.bignumber(77) ]
                }
            })

            hashRing.updateRingState(ringState)

            hashRing.getRingState().getVersion().should.be.eql({
                nodeB: 1
            })

            should.equal(hashRing.getRingState().getTokens('nodeA'), null)
            hashRing.getRingState().getTokens('nodeB').map(a => a.toHexadecimal()).should.be.eql([ math.bignumber(89).toHexadecimal(), math.bignumber(77).toHexadecimal() ])
        })

        it('should only overwrite the token assignment information that we have for another node if its version is more up to date', function() {
            let hashRing = new HashRing('nodeA')

            should.equal(hashRing.getRingState().getTokens('nodeB'), null)

            let ringState = new RingState(hashRing.getHashRange().min, hashRing.getHashRange().max)

            ringState.setTokens({
                nodeB: {
                    version: 1,
                    tokens: [ math.bignumber(89), math.bignumber(77) ]
                },
                nodeC: {
                    version: 1,
                    tokens: [ math.bignumber(1), math.bignumber(2) ]
                }
            })

            hashRing.updateRingState(ringState)
            hashRing.getRingState().getVersion().should.be.eql({
                nodeB: 1,
                nodeC: 1
            })

            should.equal(hashRing.getRingState().getTokens('nodeA'), null)
            hashRing.getRingState().getTokens('nodeB').map(a => a.toHexadecimal()).should.be.eql([ math.bignumber(89).toHexadecimal(), math.bignumber(77).toHexadecimal() ])
            hashRing.getRingState().getTokens('nodeC').map(a => a.toHexadecimal()).should.be.eql([ math.bignumber(1).toHexadecimal(), math.bignumber(2).toHexadecimal() ])

            ringState = new RingState(hashRing.getHashRange().min, hashRing.getHashRange().max)

            ringState.setTokens({
                nodeB: {
                    version: 2,
                    tokens: [ math.bignumber(100) ]
                },
                nodeC: {
                    version: 1,
                    tokens: [ math.bignumber(1000), math.bignumber(2000) ]
                }
            })

            hashRing.updateRingState(ringState)
            hashRing.getRingState().getVersion().should.be.eql({
                nodeB: 2,
                nodeC: 1
            })

            should.equal(hashRing.getRingState().getTokens('nodeA'), null)
            hashRing.getRingState().getTokens('nodeB').map(a => a.toHexadecimal()).should.be.eql([ math.bignumber(100).toHexadecimal() ])
            hashRing.getRingState().getTokens('nodeC').map(a => a.toHexadecimal()).should.be.eql([ math.bignumber(1).toHexadecimal(), math.bignumber(2).toHexadecimal() ])
        })

        it('should only update the version number if it is this node id', function() {
            let hashRing = new HashRing('nodeA')

            hashRing.getRingState().getVersion().should.be.eql({ })

            should.equal(hashRing.getRingState().getTokens('nodeB'), null)

            let ringState = new RingState(hashRing.getHashRange().min, hashRing.getHashRange().max)

            ringState.setTokens({
                nodeA: {
                    version: 1,
                    tokens: [ math.bignumber(23), math.bignumber(323), math.bignumber(32322) ]
                }
            })

            hashRing.updateRingState(ringState)

            ringState = new RingState(hashRing.getHashRange().min, hashRing.getHashRange().max)

            ringState.setTokens({
                nodeA: {
                    version: 5,
                    tokens: [ math.bignumber(555), math.bignumber(666) ]
                },
                nodeB: {
                    version: 1,
                    tokens: [ math.bignumber(89), math.bignumber(77) ]
                },
                nodeC: {
                    version: 1,
                    tokens: [ math.bignumber(1), math.bignumber(2) ]
                }
            })

            hashRing.updateRingState(ringState)
            hashRing.getRingState().getVersion().should.be.eql({
                nodeA: 6,
                nodeB: 1,
                nodeC: 1
            })

            hashRing.getRingState().getTokens('nodeA').length.should.be.eql(3)
            hashRing.getRingState().getTokens('nodeB').map(a => a.toHexadecimal()).should.be.eql([ math.bignumber(89).toHexadecimal(), math.bignumber(77).toHexadecimal() ])
            hashRing.getRingState().getTokens('nodeC').map(a => a.toHexadecimal()).should.be.eql([ math.bignumber(1).toHexadecimal(), math.bignumber(2).toHexadecimal() ])
        })
    })

    describe('#getPreferenceList', function() {
        function generateDivisionFenceposts(min, max, divisions) {
            let keyMappings = [ ]
            let divisionSize = math.divide(math.subtract(max, min), divisions)
            let currentMin = min

            // we want to test hashes at the edges and in the middle of a hash range
            for(let i = 0; i < divisions; i += 1) {
                let rangeMin = currentMin
                let rangeMax = math.subtract(currentMin.add(divisionSize), 1)
                let rangeMid = math.add(rangeMin, math.divide(divisionSize, 2))

                currentMin = currentMin.add(divisionSize)

                keyMappings.push({
                    min: rangeMin,
                    mid: rangeMid,
                    max: rangeMax
                })
            }

            return keyMappings
        }

        function getDivisionIndexFromToken(token, tokenLength, rangeDivisions) {
            let divisionSize = math.divide(math.bignumber(2).pow(tokenLength), rangeDivisions)
            let tokenDivisionIndex = math.floor(math.divide(token, divisionSize))

            return tokenDivisionIndex
        }

        function getDivisionStartFromToken(token, tokenLength, rangeDivisions) {
            let divisionSize = math.divide(math.bignumber(2).pow(tokenLength), rangeDivisions)
            let tokenDivisionIndex = math.floor(math.divide(token, divisionSize))

            return math.multiply(tokenDivisionIndex, divisionSize)
        }

        function getPreferenceList(token, tokenLength, rangeDivisions, ringStructure, replicationFactor) {
            let tokenDivisionStart = getDivisionStartFromToken(token, tokenLength, rangeDivisions)
            let first = 0

            // find position of division start
            while(first < ringStructure.length) {
                if(tokenDivisionStart.comparedTo(ringStructure[first].token) < 0) {
                    break
                }
                else if(tokenDivisionStart.comparedTo(ringStructure[first].token) > 0) {
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

            for(let i = 0; i < ringStructure.length && preferenceList.size < replicationFactor; i += 1) {
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

        /*it('if number of replias is less than the replication factor, all calls should return a list with all replicas', function() {
            let dummy = new HashRing('dummy')
            let nodes = [ ]
            let divisionFenceposts = generateDivisionFenceposts(dummy.getHashRange().min, dummy.getHashRange().max, dummy.getRangeDivisions())
            let tokenStrategyMappings = { }

            for(let i = 0; i < divisionFenceposts.length; i += 1) {
                tokenStrategyMappings['key'+Object.keys(tokenStrategyMappings).length] = divisionFenceposts[i].min
                tokenStrategyMappings['key'+Object.keys(tokenStrategyMappings).length] = divisionFenceposts[i].mid
                tokenStrategyMappings['key'+Object.keys(tokenStrategyMappings).length] = divisionFenceposts[i].max
            }

            let tokenStrategy = new StubTokenStrategy(tokenStrategyMappings)

            for(let i = 0; i < partitioner.getReplicationFactor()-1; i += 1) {
                nodes.push(new HashRing('node'+i))
            }

            let tokens = [ ]
            let tokensUpdate = { }
            let ringState = new RingState(nodes[0].getHashRange().min, nodes[0].getHashRange().max)

            for(let node of nodes) {
                let initTokens = node.generateTokens()

                tokens.push(initTokens)

                tokensUpdate[node.nodeID] = {
                    version: 1,
                    tokens: initTokens
                }
            }

            ringState.setTokens(tokensUpdate)

            for(let node of nodes) {
                node.updateRingState(ringState)
            }

            let ringStructure = [ ]

            for(let i = 0; i < nodes.length; i += 1) {
                let nodeTokenList = tokens[i]

                for(let j = 0; j < nodeTokenList.length; j += 1)  {
                    ringStructure.push({ node: 'node'+i, token: nodeTokenList[j] })
                }
            }

            ringStructure.sort(function(a, b) {
                if(a.token.comparedTo(b.token) < 0) {
                    return -1
                }
                else if(a.token.comparedTo(b.token) > 0) {
                    return 1
                }
                else {
                    if(a.node < b.node) {
                        return -1
                    }
                    else {
                        return 1
                    }
                }
            })

            let keys = Object.keys(tokenStrategyMappings)
            let preferenceLists = keys.map(k => nodes[0].getPreferenceList(k))

            for(let i = 0; i < keys.length; i += 1) {
                let token = tokenStrategyMappings[keys[i]]
                let expectedPreferenceList = getPreferenceList(token, tokenStrategy.tokenLength(), dummy.getRangeDivisions(), ringStructure, partitioner.getReplicationFactor())
                let actualPreferenceList = preferenceLists[i]

                new Set(expectedPreferenceList).should.be.eql(new Set(actualPreferenceList))
            }
        })*/

        it('if number of replicas is equal to the replication factor, all calls should return a list with all replicas', function() {
            let dummy = new HashRing('dummy')
            let nodes = [ ]
            let divisionFenceposts = generateDivisionFenceposts(dummy.getHashRange().min, dummy.getHashRange().max, dummy.getRangeDivisions())
            let tokenStrategyMappings = { }

            for(let i = 0; i < divisionFenceposts.length; i += 1) {
                tokenStrategyMappings['key'+Object.keys(tokenStrategyMappings).length] = divisionFenceposts[i].min
                tokenStrategyMappings['key'+Object.keys(tokenStrategyMappings).length] = divisionFenceposts[i].mid
                tokenStrategyMappings['key'+Object.keys(tokenStrategyMappings).length] = divisionFenceposts[i].max
            }

            let tokenStrategy = new StubTokenStrategy(tokenStrategyMappings)

            for(let i = 0; i < partitioner.getReplicationFactor(); i += 1) {
                nodes.push(new HashRing('node'+i))
            }

            let tokens = [ ]
            let tokensUpdate = { }
            let ringState = new RingState(nodes[0].getHashRange().min, nodes[0].getHashRange().max)

            for(let node of nodes) {
                let initTokens = node.generateTokens()

                tokens.push(initTokens)

                tokensUpdate[node.nodeID] = {
                    version: 1,
                    tokens: initTokens
                }
            }

            ringState.setTokens(tokensUpdate)

            for(let node of nodes) {
                node.updateRingState(ringState)
            }

            let ringStructure = [ ]

            for(let i = 0; i < nodes.length; i += 1) {
                let nodeTokenList = tokens[i]

                for(let j = 0; j < nodeTokenList.length; j += 1)  {
                    ringStructure.push({ node: 'node'+i, token: nodeTokenList[j] })
                }
            }

            ringStructure.sort(function(a, b) {
                if(a.token.comparedTo(b.token) < 0) {
                    return -1
                }
                else if(a.token.comparedTo(b.token) > 0) {
                    return 1
                }
                else {
                    if(a.node < b.node) {
                        return -1
                    }
                    else {
                        return 1
                    }
                }
            })

            let keys = Object.keys(tokenStrategyMappings)
            let preferenceLists = keys.map(k => nodes[0].getPreferenceList(k))
            for(let i = 0; i < keys.length; i += 1) {
                let token = tokenStrategyMappings[keys[i]]
                let expectedPreferenceList = getPreferenceList(token, tokenStrategy.tokenLength(), dummy.getRangeDivisions(), ringStructure, partitioner.getReplicationFactor())
                let actualPreferenceList = preferenceLists[i]

                new Set(expectedPreferenceList).should.be.eql(new Set(actualPreferenceList))
            }
        })

        it('if number of replicas is greater than the replication factor, all calls should return a list of replicas whose length is the replication factor', function() {
            let dummy = new HashRing('dummy')
            let nodes = [ ]
            let divisionFenceposts = generateDivisionFenceposts(dummy.getHashRange().min, dummy.getHashRange().max, dummy.getRangeDivisions())
            let tokenStrategyMappings = { }

            for(let i = 0; i < divisionFenceposts.length; i += 1) {
                tokenStrategyMappings['key'+Object.keys(tokenStrategyMappings).length] = divisionFenceposts[i].min
                tokenStrategyMappings['key'+Object.keys(tokenStrategyMappings).length] = divisionFenceposts[i].mid
                tokenStrategyMappings['key'+Object.keys(tokenStrategyMappings).length] = divisionFenceposts[i].max
            }

            let tokenStrategy = new StubTokenStrategy(tokenStrategyMappings)

            for(let i = 0; i < partitioner.getReplicationFactor()+1; i += 1) {
                nodes.push(new HashRing('node'+i))
            }


            let tokens = [ ]
            let tokensUpdate = { }
            let ringState = new RingState(nodes[0].getHashRange().min, nodes[0].getHashRange().max)

            for(let node of nodes) {
                let initTokens = node.generateTokens()

                tokens.push(initTokens)

                tokensUpdate[node.nodeID] = {
                    version: 1,
                    tokens: initTokens
                }

                node.tokenStrategy = tokenStrategy
            }

            ringState.setTokens(tokensUpdate)

            for(let node of nodes) {
                node.updateRingState(ringState)
            }

            let ringStructure = [ ]

            for(let i = 0; i < nodes.length; i += 1) {
                let nodeTokenList = tokens[i]

                for(let j = 0; j < nodeTokenList.length; j += 1)  {
                    ringStructure.push({ node: 'node'+i, token: nodeTokenList[j] })
                }
            }

            ringStructure.sort(function(a, b) {
                if(a.token.comparedTo(b.token) < 0) {
                    return -1
                }
                else if(a.token.comparedTo(b.token) > 0) {
                    return 1
                }
                else {
                    if(a.node < b.node) {
                        return -1
                    }
                    else {
                        return 1
                    }
                }
            })

            let keys = Object.keys(tokenStrategyMappings)
            let i = 0
            let preferenceLists = keys.map(k => nodes[0].getPreferenceList(k))

            for(let i = 0; i < keys.length; i += 1) {
                let token = tokenStrategyMappings[keys[i]]
                let expectedPreferenceList = getPreferenceList(token, tokenStrategy.tokenLength(), dummy.getRangeDivisions(), ringStructure, partitioner.getReplicationFactor())
                let actualPreferenceList = preferenceLists[i]

                new Set(expectedPreferenceList).should.be.eql(new Set(actualPreferenceList))
            }
        })
    })
})

describe('RulePartitioner', function() {
    const RulePartitioner = require('../index.js').RulePartitioner

    it('should work', function() {
        let rulePartitionerA = new RulePartitioner('nodeA')
        let rulePartitionerB = new RulePartitioner('nodeB')
        let rulePartitionerC = new RulePartitioner('nodeC')

        rulePartitionerA.updateRelays(new Set([ 'nodeA', 'nodeB', 'nodeC' ]))
        rulePartitionerB.updateRelays(new Set([ 'nodeA', 'nodeB', 'nodeC' ]))
        rulePartitionerC.updateRelays(new Set([ 'nodeA', 'nodeB', 'nodeC' ]))

        for(let i = 0; i < 1000; i += 1) {
            let count = 0

            count += rulePartitionerA.isExecutedByMe('key'+i)
            count += rulePartitionerB.isExecutedByMe('key'+i)
            count += rulePartitionerC.isExecutedByMe('key'+i)

            count.should.be.eql(1)
        }
    })
})