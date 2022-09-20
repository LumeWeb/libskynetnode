import { progressiveFetchResult } from "libskynet";
declare function progressiveFetch(endpoint: string, fetchOpts: any, portals: string[], verifyFunction: any): Promise<progressiveFetchResult>;
export { progressiveFetch, progressiveFetchResult };
