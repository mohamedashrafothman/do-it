import { Types } from "mongoose";

export default interface Label {
	name: string;
	slug: string;
	user: Types.ObjectId;
	list: Types.ObjectId;
	steps: Types.ObjectId[];
	labels?: Types.ObjectId[];
}
