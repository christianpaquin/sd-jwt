export enum LOG_LEVEL {
    DEBUG = 0,
    INFO = 1,
    ERROR = 2
}

const DEFAULT_LOG_LEVEL = LOG_LEVEL.DEBUG;

export function Log(message: any, level: LOG_LEVEL = LOG_LEVEL.INFO) {
    if (level >= DEFAULT_LOG_LEVEL) {
        console.log(message, '\n');
    }
}