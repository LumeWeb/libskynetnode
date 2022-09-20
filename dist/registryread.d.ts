interface readRegistryEntryResult {
    exists: boolean;
    data: Uint8Array;
    revision: bigint;
}
declare function readRegistryEntry(pubkey: Uint8Array, datakey: Uint8Array): Promise<readRegistryEntryResult>;
export { readRegistryEntry };
