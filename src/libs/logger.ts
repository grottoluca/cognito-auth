import winston from 'winston'

/** Custom log levels with priority */
const levels = {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    debug: 4,
}

/** Determine log level based on environment */
const level = (): string => {
    // const env = process.env.NODE_ENV || 'development'
    // const isDevelopment = env === 'development'
    // return isDevelopment ? 'debug' : 'warn'
    return 'debug'
}

/** Color mapping for log levels */
const colors = {
    error: 'red',
    warn: 'yellow',
    info: 'green',
    http: 'magenta',
    debug: 'white',
}

winston.addColors(colors)

/** Log format configuration */
const format = winston.format.combine(
    winston.format.timestamp({
        format: 'YYYY-MM-DD hh:mm:ss'
    }),
    winston.format.splat(),
    winston.format.simple(),
    winston.format.printf(
        info => `${info.timestamp}  ${info.level} : ${info.message}`
    )
)

/** Transport configurations for logging */
const transports: winston.transport[] = [
    new winston.transports.Console({
        format: winston.format.combine(winston.format.colorize({ all: true }), format)
    }),
    new winston.transports.File({
        format: winston.format.combine(winston.format.uncolorize(), format),
        filename: 'logs/error.log',
        level: 'error',
        maxsize: 10000000
    }),
    new winston.transports.File({
        format: winston.format.combine(winston.format.uncolorize(), format),
        filename: 'logs/all.log',
        maxsize: 10000000,

    })
]

/** Winston logger instance */
const logger = winston.createLogger({
    level: level(),
    levels,
    format,
    transports,
})

/** Stream interface for HTTP logging middleware (e.g., morgan) */
export const stream = {
    write: (message: string): void => {
        logger.http(message)
    }
}

export default logger
