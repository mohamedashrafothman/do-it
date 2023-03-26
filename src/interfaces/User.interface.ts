export default interface User {
	email: string;
	name: string;
	slug?: string;
	password: string;
	picture: string;
	is_active: boolean;
	is_verified: boolean;
	google?: string;
	facebook?: string;
}
