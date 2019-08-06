export class ThreadApi {
    apiFunction: string;
    apiArguments: any[];

    result: any = null;
    consumed: boolean = false;

    constructor(apiFunction, apiArguments) {
        this.apiFunction = apiFunction;
        this.apiArguments = apiArguments;
    }
}