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

class MoodBuilder {
    constructor() {
    }

    createMood(resources) {
        if(resources.length == 0) {
            return Promise.reject(new Error('No resources specified'))
        }
        
        let selection = ''
        
        resources = new Set(resources)
        
        for(let resource of resources) {
            selection += 'id="' + resource + '" or '
        }
        
        let stateSnapshot = { }
        
        selection = selection.substring(0, selection.length - ' or '.length)
    
        // get a snapshot of the current device states
        return dev$.select(selection).get().then((resourceStates) => {
            for(let resource of resourceStates) {
                if(!resourceStates[resource].receivedResponse) {
                    continue
                }
                
                if(resourceStates[resource].response.error) {
                    continue
                }
                
                if(resourceStates[resource].response.result == null || typeof resourceStates[resource].response.result != 'object') {
                    continue
                }
                
                stateSnapshot[resource] = resourceStates[resource].response.result
            }
            
            if(Object.keys(stateSnapshot).length < resources.size) {
                throw new Error('Some resources are unreachable')
            }
        }).then(() => {
            let newMoodID = dev$.uuid()
            
            
        })
    }
    
    getMood(id) {
    }
    
    listMoods() {
    }
    
    updateMood(id, resources) {
    }
    
    deleteMood(id) {
    }
    
    applyMood(id) {
    }
}

function listMoods(ddbClient) {
    var moods = { }

    function next(error, result) {
        if(error) {
            return
        }

        if(result.value == null) {
            return
        }

        var suffix = result.key.substring(result.prefix.length)
        var moodName
        var configuredMoodName
        var configuredMoodState

        if(result.key.endsWith('.state')) {
            moodName = suffix.substring(0, suffix.length-'.state'.length)

            try {
                configuredMoodState = JSON.parse(result.value)
            }
            catch(error) {

            }
        }
        else if(result.key.endsWith('.name')) {
            moodName = suffix.substring(0, suffix.length-'.name'.length)
            configuredMoodName = result.value
        }
        else {
            return
        }

        moods[moodName] = moods[moodName] || {
            states: { },
            name: moodName
        }

        if(configuredMoodName) {
            moods[moodName].name = configuredMoodName
        }

        if(configuredMoodState) {
            moods[moodName].states = configuredMoodState
        }
    }

    return ddbClient.lww.getMatches(moodsPrefix + 'moods.', next).then(function() {
        return moods
    })
}

function getMood(ddbClient, moodName) {
    var mood = { 
        states: { },
        name: moodName
    }

    return ddbClient.lww.get([
        moodsPrefix + 'moods.' + moodName + '.state',
        moodsPrefix + 'moods.' + moodName + '.name'
    ]).then(function(results) {
        if(results[1] != null && results[1].value != null) {
            mood.name = results[1].value
        }

        if(results[0] == null || results[0].value == null) {
            return
        }
        
        var statesMap = JSON.parse(results[0].value)

        if(statesMap && typeof statesMap == 'object') {
            mood.states = statesMap
        }
    }).then(function() {
        return mood
    })
}

function putMood(ddbClient, moodName, mood) {
    return ddbClient.lww.batch([
        {
            type: 'put',
            key: moodsPrefix + 'moods.' + moodName + '.state',
            value: JSON.stringify(mood.states),
            context: ''
        },
        {
            type: 'put',
            key: moodsPrefix + 'moods.' + moodName + '.name',
            value: mood.name,
            context: ''
        }
    ])
}

function deleteMood(ddbClient, moodName) {
    return ddbClient.lww.batch([
        {
            type: 'delete',
            key: moodsPrefix + 'moods.' + moodName + '.state',
            context: ''
        },
        {
            type: 'delete',
            key: moodsPrefix + 'moods.' + moodName + '.name',
            context: ''
        }
    ])   
}
    
module.exports = MoodBuilder
