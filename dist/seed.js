"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateSeedPhraseRandom = void 0;
const crypto_1 = require("crypto");
const libskynet_1 = require("libskynet");
// generateSeedPhraseRandom will randomly generate and verify a seed phrase for the user.
function generateSeedPhraseRandom() {
    const buf = Uint8Array.from((0, crypto_1.randomBytes)(32));
    const str = (0, libskynet_1.bufToB64)(buf);
    const [sp, errGSPD] = (0, libskynet_1.generateSeedPhraseDeterministic)(str);
    if (errGSPD !== null) {
        return ["", (0, libskynet_1.addContextToErr)(errGSPD, "unable to generate seed from string")];
    }
    return [sp, null];
}
exports.generateSeedPhraseRandom = generateSeedPhraseRandom;
