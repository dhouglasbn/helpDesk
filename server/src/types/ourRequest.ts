import type { Request } from "express"

export interface UserInToken {
	id: string
	email: string
	role: string
}

export interface OurRequest extends Request {
	user?: UserInToken
	file?: Express.Multer.File
}
