import { DwarfProcessInfo } from "./DwarfProcessInfo";

export interface DwarfInitResponse {
    apiFunctions: ApiFunction[];
    coreVersion: string;
    fridaVersion: string;
    javaAvailable: boolean;
    JNITracer?: { available: string[] };
    moduleBlacklist: string[];
    objcAvailable: boolean;
    processInfo: DwarfProcessInfo;
}
