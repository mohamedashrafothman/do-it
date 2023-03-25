import { VarsTypes } from "utils/vars";
import { type IUserDocument } from "../models/User";

export { };

declare global {
	namespace Express {
		// eslint-disable-next-line @typescript-eslint/no-empty-interface
		export interface User extends IUserDocument {}
		export interface Request {
			vars?: VarsTypes;
			lang?: string;
			roles?: VarsTypes["roles"];
			prevPath?: string;
			prevPrevPath?: string;
		}
		export interface Response {
			back: () => unknown;
		}
	}
}
