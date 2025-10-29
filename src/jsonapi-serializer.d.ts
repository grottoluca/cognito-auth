declare module 'jsonapi-serializer' {
    export class Error {
        constructor(errors: {
            status: string
            title: string
            detail: string
        }): any
    }
}
