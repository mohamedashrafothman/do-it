import vars from "../utils/vars";

export default interface User {
	email: string;
	name: string;
	slug?: string;
	password: string;
	picture: string;
	is_active: boolean;
	is_verified: boolean;
	role: (typeof vars.roles)[keyof typeof vars.roles];
	google?: string;
	facebook?: string;
}
