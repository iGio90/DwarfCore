/**
 Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>
 **/

import "./_global_funcs"

import { DwarfCore } from "./dwarf";
import { ThreadApi } from "./thread_api";


global.Dwarf = DwarfCore.getInstance();

rpc.exports = {
    api: function (tid, apiFunction, apiArguments) {
        if (DEBUG) {
            logDebug('[' + tid + '] RPC-API: ' + apiFunction + ' | ' +
                'args: ' + apiArguments + ' (' + Process.getCurrentThreadId() + ')');
        }

        if (typeof apiArguments === 'undefined' || apiArguments === null) {
            apiArguments = [];
        }

        if (Object.keys(Dwarf.threadContexts).length > 0) {
            const threadContext = Dwarf.threadContexts[tid];
            if (isDefined(threadContext)) {
                const threadApi = new ThreadApi(apiFunction, apiArguments);
                threadContext.apiQueue.push(threadApi);
                const start = Date.now();
                while (!threadApi.consumed) {
                    Thread.sleep(0.5);
                    if (DEBUG) {
                        logDebug('[' + tid + '] RPC-API: ' + apiFunction + ' waiting for api result');
                    }
                    if (Date.now() - start > 3 * 1000) {
                        threadApi.result = '';
                        break;
                    }
                }

                let ret = threadApi.result;
                if (!isDefined(ret)) {
                    ret = '';
                }
                if (DEBUG) {
                    logDebug('[' + tid + '] RPC-API: ' + apiFunction + ' api result: ' + ret);
                }
                return ret;
            }
        }

        return Dwarf.getApi()[apiFunction].apply(this, apiArguments)
    },
    init: function (breakStart, debug, spawned, globalApiFuncs?:Array<string>) {
        //init dwarf
        Dwarf.init(breakStart, debug, spawned, globalApiFuncs);
    },
    keywords: function () {
        const map = [];
        Object.getOwnPropertyNames(global).forEach(function (name) {
            map.push(name);

            // second level
            if (isDefined(global[name])) {
                Object.getOwnPropertyNames(global[name]).forEach(function (sec_name) {
                    map.push(sec_name);
                });
            }
        });
        return uniqueBy(map);
    }
};
