"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.readRegistryEntry = void 0;
const libskynet_1 = require("libskynet");
const progressivefetch_js_1 = require("./progressivefetch.js");
// readRegistryEntry will read and verify a registry entry. The tag strings
// will be hashed with the user's seed to produce the correct entropy.
function readRegistryEntry(pubkey, datakey) {
    return new Promise((resolve, reject) => {
        const pubkeyHex = (0, libskynet_1.bufToHex)(pubkey);
        const datakeyHex = (0, libskynet_1.bufToHex)(datakey);
        const endpoint = "/skynet/registry?publickey=ed25519%3A" + pubkeyHex + "&datakey=" + datakeyHex;
        const verifyFunc = function (response) {
            return (0, libskynet_1.verifyRegistryReadResponse)(response, pubkey, datakey);
        };
        (0, progressivefetch_js_1.progressiveFetch)(endpoint, {}, libskynet_1.defaultPortalList, verifyFunc).then((result) => {
            // Check for a success.
            if (result.success === true) {
                result.response
                    .json()
                    .then((j) => {
                    resolve({
                        exists: true,
                        data: j.data,
                        revision: BigInt(j.revision),
                    });
                })
                    .catch((err) => {
                    reject((0, libskynet_1.addContextToErr)(err, "unable to parse response despite passing verification"));
                });
                return;
            }
            // Check for 404.
            for (let i = 0; i < result.responsesFailed.length; i++) {
                if (result.responsesFailed[i].status === 404) {
                    resolve({
                        exists: false,
                        data: new Uint8Array(0),
                        revision: 0n,
                    });
                    return;
                }
            }
            reject("unable to read registry entry\n" + JSON.stringify(result));
        });
    });
}
exports.readRegistryEntry = readRegistryEntry;
