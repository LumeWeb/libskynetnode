"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.upload = void 0;
const libskynet_1 = require("libskynet");
const progressivefetch_js_1 = require("./progressivefetch.js");
// upload will upload the provided fileData to Skynet using the provided
// metadata and then return the resulting skylink. Upload is a secure function
// that computes the skylink of the upload locally, ensuring that the server
// cannot return a malicious skylink and convince a user to run modified code.
function upload(fileData, metadata) {
    return new Promise((resolve, reject) => {
        // Check that this is a small file.
        if (fileData.length > 4 * 1000 * 1000) {
            reject("currently only small uploads are supported, please use less than 4 MB");
            return;
        }
        // Encode the metadata after checking that it is valid.
        const errVSM = (0, libskynet_1.validateSkyfileMetadata)(metadata);
        if (errVSM !== null) {
            reject((0, libskynet_1.addContextToErr)(errVSM, "upload is using invalid metadata"));
            return;
        }
        const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
        // Build the layout of the skyfile.
        const layoutBytes = new Uint8Array(99);
        let offset = 0;
        layoutBytes[offset] = 1; // Set the Version
        offset += 1;
        const [filesizeBytes, errU641] = (0, libskynet_1.encodeU64)(BigInt(fileData.length));
        if (errU641 !== null) {
            reject((0, libskynet_1.addContextToErr)(errU641, "unable to encode fileData length"));
            return;
        }
        layoutBytes.set(filesizeBytes, offset);
        offset += 8;
        const [mdSizeBytes, errU642] = (0, libskynet_1.encodeU64)(BigInt(metadataBytes.length));
        if (errU642 !== null) {
            reject((0, libskynet_1.addContextToErr)(errU642, "unable to encode metadata bytes length"));
            return;
        }
        layoutBytes.set(mdSizeBytes, offset);
        offset += 8;
        const [fanoutSizeBytes, errU643] = (0, libskynet_1.encodeU64)(0n);
        if (errU643 !== null) {
            reject((0, libskynet_1.addContextToErr)(errU643, "unable to encode fanout bytes length"));
            return;
        }
        layoutBytes.set(fanoutSizeBytes, offset);
        offset += 8;
        layoutBytes[offset] = 0; // Set the fanout data pieces
        offset += 1;
        layoutBytes[offset] = 0; // Set the fanout parity pieces
        offset += 1;
        layoutBytes[offset + 7] = 1; // Set the cipher type
        offset += 8;
        if (offset + 64 !== 99) {
            reject("error when building the layout bytes, got wrong final offset");
            return;
        }
        // Build the base sector.
        const totalSize = layoutBytes.length + metadataBytes.length + fileData.length;
        if (totalSize > 1 << 22) {
            reject("error when building the base sector: total sector is too large");
            return;
        }
        const baseSector = new Uint8Array(1 << 22);
        offset = 0;
        baseSector.set(layoutBytes, offset);
        offset += layoutBytes.length;
        baseSector.set(metadataBytes, offset);
        offset += metadataBytes.length;
        baseSector.set(fileData, offset);
        // Compute the Skylink of this file.
        const [sectorRoot, errBMR] = (0, libskynet_1.blake2bMerkleRoot)(baseSector);
        if (errBMR !== null) {
            reject((0, libskynet_1.addContextToErr)(errBMR, "unable to create bitfield for skylink"));
            return;
        }
        const skylinkBytes = new Uint8Array(34);
        const [bitfield, errSV1B] = (0, libskynet_1.skylinkV1Bitfield)(BigInt(totalSize));
        if (errSV1B !== null) {
            reject((0, libskynet_1.addContextToErr)(errSV1B, "unable to create bitfield for skylink"));
            return;
        }
        skylinkBytes.set(bitfield, 0);
        skylinkBytes.set(sectorRoot, 2);
        // Build the header for the upload call.
        const header = new Uint8Array(92);
        const [headerMetadataPrefix, errU644] = (0, libskynet_1.encodeU64)(15n);
        if (errU644 !== null) {
            reject((0, libskynet_1.addContextToErr)(errU644, "unable to encode header metadata length"));
            return;
        }
        const headerMetadata = new TextEncoder().encode("Skyfile Backup\n");
        const [versionPrefix, errU645] = (0, libskynet_1.encodeU64)(7n);
        if (errU645 !== null) {
            reject((0, libskynet_1.addContextToErr)(errU645, "unable to encode version prefix length"));
            return;
        }
        const version = new TextEncoder().encode("v1.5.5\n");
        const [skylinkPrefix, errU646] = (0, libskynet_1.encodeU64)(46n);
        if (errU646 !== null) {
            reject((0, libskynet_1.addContextToErr)(errU646, "unable to encode skylink length"));
            return;
        }
        const skylink = (0, libskynet_1.bufToB64)(skylinkBytes);
        offset = 0;
        header.set(headerMetadataPrefix, offset);
        offset += 8;
        header.set(headerMetadata, offset);
        offset += 15;
        header.set(versionPrefix, offset);
        offset += 8;
        header.set(version, offset);
        offset += 7;
        header.set(skylinkPrefix, offset);
        offset += 8;
        header.set(new TextEncoder().encode(skylink), offset);
        // Build the full request body.
        const reqBody = new Uint8Array((1 << 22) + 92);
        reqBody.set(header, 0);
        reqBody.set(baseSector, 92);
        // Call progressiveFetch to perform the upload.
        const endpoint = "/skynet/restore";
        const fetchOpts = {
            method: "post",
            body: reqBody,
        };
        // Establish the function that verifies the result is correct.
        const verifyFunction = function (response) {
            return new Promise((resolve) => {
                response
                    .json()
                    .then((j) => {
                    if (!("skylink" in j)) {
                        resolve("response is missing the skylink field\n" + JSON.stringify(j));
                        return;
                    }
                    if (j.skylink !== skylink) {
                        resolve("wrong skylink was returned, expecting " + skylink + " but got " + j.skylink);
                        return;
                    }
                    resolve(null);
                })
                    .catch((err) => {
                    resolve((0, libskynet_1.addContextToErr)(err, "unable to read response body"));
                });
            });
        };
        (0, progressivefetch_js_1.progressiveFetch)(endpoint, fetchOpts, libskynet_1.defaultPortalList, verifyFunction).then((result) => {
            result.response
                .json()
                .then((j) => {
                resolve(j.skylink);
            })
                .catch((err) => {
                reject((0, libskynet_1.addContextToErr)(err, "unable to read response body, despite verification of response succeeding"));
            });
        });
    });
}
exports.upload = upload;
