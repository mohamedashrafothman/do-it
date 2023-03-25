declare namespace Express {
	type RequestExpress = import("express-serve-static-core").Request;
	type SessionExpress = import("express-session").Session;
	type SessionDataExpress = import("express-session").SessionData;
	export interface Request {
		session: SessionExpress &
			Partial<SessionDataExpress> & {
				returnTo?: string;
			};
	}
}
