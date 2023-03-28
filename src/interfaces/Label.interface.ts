import { Types } from "mongoose";

export default interface Label {
	user: Types.ObjectId;
	name: string;
	emoji: string;
	slug: string;
}
