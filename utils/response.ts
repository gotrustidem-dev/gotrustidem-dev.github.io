


interface GTIDEM_response  {

    readonly status: number;
    readonly FW: ArrayBuffer;
    readonly SW: ArrayBuffer;
    readonly PIN_retry: number;
    readonly credential: number;

    
}

declare var GTIDEM_response: {
    prototype: GTIDEM_response;
    new(): GTIDEM_response;
};